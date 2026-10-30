#!/usr/bin/env python3
"""Phase II: train the function classifier on the DEVELOPMENT set, tune on development only, score the frozen
held-out set once, and write the ablation (P2.7 / P2.8).

  python eval/phase2_ml.py [--skip-heldout]

Protocol (docs/PHASE2_ML.md):
  * training data: dataset/functions/labels.jsonl.gz (development images only);
  * the single tunable, k = minimum number of functions classified as family F for F to count as present in an
    image, is chosen by leave-one-optimisation-level-out cross-validation on development data, never on held-out;
  * the held-out set (tag heldout-frozen-1) is predicted once with models fitted on all development data.
"""

import argparse
import gzip
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cbomscan import image, mlfeatures as mf  # noqa: E402
from cbomscan.functions import recover_functions  # noqa: E402
from cbomscan.taxonomy import SCORED_FAMILIES  # noqa: E402

DEV = ROOT / "dataset" / "out_esp32" / "samples"
HELD = ROOT / "dataset" / "heldout"
CACHE = ROOT / "dataset" / "functions" / "cache"
OUT = ROOT / "results" / "phase2"
CLASSES = SCORED_FAMILIES + ["support", "other"]
MBED = ("https_request", "simple_ota", "mqtt_ssl", "https_mbedtls")
VARIANTS = {"ml:ins": mf.GROUPS["ins"], "ml:const": mf.GROUPS["const"],
            "ml:ins+const": sorted(mf.GROUPS["ins"] + mf.GROUPS["const"])}


def load_dev():
    rows = [json.loads(l) for l in gzip.open(ROOT / "dataset/functions/labels.jsonl.gz", "rt", encoding="utf-8")]
    by = defaultdict(list)
    for r in rows:
        by[r["sample"]].append(r)
    return by


def dev_matrix():
    f = CACHE / "dev.npz"
    if f.exists():
        z = np.load(f, allow_pickle=False)   # numeric + unicode arrays only; no pickle needed
        return z["X"], z["y"], z["sample"], z["opt"]
    by = load_dev()
    Xs, ys, ss, oo = [], [], [], []
    for name, rs in sorted(by.items()):
        fw = image.load(str(DEV / name / "firmware.bin"))
        funcs = recover_functions(fw)
        assert [x.start for x in funcs] == [r["start"] for r in rs], name
        X, _ = mf.image_features(fw, funcs)
        Xs.append(X)
        ys += [CLASSES.index(r["label"]) for r in rs]
        ss += [name] * len(rs)
        oo += [rs[0]["opt"]] * len(rs)
    X, y, s, o = np.vstack(Xs), np.array(ys), np.array(ss), np.array(oo)
    CACHE.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(f, X=X, y=y, sample=s, opt=o)
    return X, y, s, o


def fit(X, y):
    cnt = Counter(y.tolist())
    w = np.array([(len(y) / (len(cnt) * cnt[c])) ** 0.5 for c in y], dtype=np.float64)
    m = HistGradientBoostingClassifier(max_iter=60, learning_rate=0.15, max_leaf_nodes=31, random_state=0,
                                       early_stopping=False)
    m.fit(X, y, sample_weight=w)
    return m


def save_model(m, cols, k, prec, n_funcs, n_images):
    """Persist the shipped model (trusted-source pickle via joblib) plus metadata with its SHA-256."""
    import hashlib
    import joblib
    import sklearn
    d = ROOT / "models"
    d.mkdir(exist_ok=True)
    joblib.dump(m, d / "function_classifier.joblib", compress=3)
    meta = {"classes": CLASSES, "columns": list(cols), "n_features": len(mf.NAMES), "k": k,
            "confidence_by_family": prec, "confidence_source": "development leave-one-opt-out CV image-level precision at k",
            "sklearn": sklearn.__version__, "train_functions": n_funcs, "train_images": n_images,
            "sha256": hashlib.sha256((d / "function_classifier.joblib").read_bytes()).hexdigest()}
    (d / "function_classifier.json").write_text(json.dumps(meta, indent=1))


def counts_per_image(pred, samples):
    """{image: {family: number of functions predicted as that family}} for the 13 scored families."""
    out = defaultdict(Counter)
    for p, s in zip(pred, samples):
        if CLASSES[p] in SCORED_FAMILIES:
            out[s][CLASSES[p]] += 1
    return out


def present(counts, k):
    return {f for f, n in counts.items() if n >= k}


def micro(truth, pred, excl=None):
    tp = fp = fn = 0
    for s in truth:
        for f in SCORED_FAMILIES:
            if excl and excl(s, f):
                continue
            t, p = f in truth[s], f in pred.get(s, set())
            tp += t and p
            fp += p and not t
            fn += t and not p
    P = tp / (tp + fp) if tp + fp else 0.0
    R = tp / (tp + fn) if tp + fn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, P=P, R=R, F1=(2 * P * R / (P + R)) if P + R else 0.0)


def per_family(truth, pred):
    res = {}
    for f in SCORED_FAMILIES:
        tp = sum(1 for s in truth if f in truth[s] and f in pred.get(s, set()))
        fp = sum(1 for s in truth if f not in truth[s] and f in pred.get(s, set()))
        fn = sum(1 for s in truth if f in truth[s] and f not in pred.get(s, set()))
        res[f] = (tp, fp, fn)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-heldout", action="store_true")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    X, y, samples, opts = dev_matrix()
    print(f"dev: {X.shape[0]} functions x {X.shape[1]} features, {len(set(samples.tolist()))} images "
          f"({time.time()-t0:.0f}s)", flush=True)
    dev_truth = {}
    for s in set(samples.tolist()):
        dev_truth[s] = set(json.loads((DEV / s / "truth.json").read_text())["present_families"])

    # --- leave-one-optimisation-level-out CV, ins+const, to choose k and report development accuracy
    cols = VARIANTS["ml:ins+const"]
    oof = np.zeros(len(y), dtype=int)
    for o in sorted(set(opts.tolist())):
        te = opts == o
        m = fit(X[~te][:, cols], y[~te])
        oof[te] = m.predict(X[te][:, cols])
        print(f"  cv fold leave-out {o}: function accuracy {np.mean(oof[te] == y[te]):.3f} ({time.time()-t0:.0f}s)",
              flush=True)
    dcounts = counts_per_image(oof, samples.tolist())
    sweep = {}
    for k in (1, 2, 3, 5, 8, 12, 20):
        sweep[k] = micro(dev_truth, {s: present(dcounts[s], k) for s in dev_truth})
    best_k = max(sweep, key=lambda k: (sweep[k]["F1"], k))
    print("dev CV image-level by k:", {k: round(v["F1"], 4) for k, v in sweep.items()}, "-> k =", best_k, flush=True)
    dpred = {s: present(dcounts[s], best_k) for s in dev_truth}
    prec = {}
    for f, (tp, fp, fn) in per_family(dev_truth, dpred).items():
        if tp + fp:
            prec[f] = tp / (tp + fp)
    fam_oof = {c: float(np.mean(oof[y == CLASSES.index(c)] == CLASSES.index(c))) for c in SCORED_FAMILIES}
    res = {"k": best_k, "dev_cv_sweep": {str(k): v for k, v in sweep.items()},
           "dev_cv_function_accuracy": float(np.mean(oof == y)),
           "dev_cv_image_precision_by_family": prec, "dev_cv_function_recall_by_family": fam_oof}
    (OUT / "dev_cv.json").write_text(json.dumps(res, indent=1))
    if a.skip_heldout:
        return

    # --- final models on all development data, one prediction pass on the frozen held-out set
    hidx = json.loads((HELD / "index.json").read_text())
    htruth = {r["sample"]: set(r["present_families"]) for r in hidx}
    hX, hs = [], []
    for r in hidx:
        fw = image.load(str(HELD / "samples" / r["sample"] / "firmware.bin"))
        funcs = recover_functions(fw)
        Xi, _ = mf.image_features(fw, funcs)
        hX.append(Xi)
        hs += [r["sample"]] * len(funcs)
    hX = np.vstack(hX)
    print(f"held-out: {hX.shape[0]} functions ({time.time()-t0:.0f}s)", flush=True)
    ml = {}
    for name, cols in VARIANTS.items():
        m = fit(X[:, cols], y)
        if name == "ml:ins+const":
            save_model(m, cols, best_k, prec, X.shape[0], len(set(samples.tolist())))
        pc = counts_per_image(m.predict(hX[:, cols]), hs)
        ml[name] = {s: dict(pc[s]) for s in htruth}
        print(f"  fitted {name} ({time.time()-t0:.0f}s)", flush=True)
    (OUT / "heldout_ml_counts.json").write_text(json.dumps(ml, indent=1))

    # --- systems on held-out
    ps = {r["sample"]: r for r in json.loads((ROOT / "results/heldout/per_sample.json").read_text())}
    systems = {k: {s: set(ps[s][k]) for s in htruth} for k in ("strings-baseline", "rules:constants", "rules:all")}
    for name in VARIANTS:
        systems[name] = {s: present(Counter(ml[name][s]), best_k) for s in htruth}
    systems["rules:all + ml:ins+const"] = {s: systems["rules:all"][s] | systems["ml:ins+const"][s] for s in htruth}
    systems["rules:all + ml:ins"] = {s: systems["rules:all"][s] | systems["ml:ins"][s] for s in htruth}
    systems["rules:all + ml:const"] = {s: systems["rules:all"][s] | systems["ml:const"][s] for s in htruth}
    md5_excl = lambda s, f: f == "MD5" and s.startswith(MBED)  # noqa: E731

    def sel(pred_fn):
        return {s: htruth[s] for s in htruth if pred_fn(s)}

    groups = {"all 32": lambda s: True, "mbedTLS (16)": lambda s: s.startswith(MBED),
              "wolfSSL (16)": lambda s: not s.startswith(MBED)}
    for o in ("O0", "Og", "O2", "Os"):
        groups[f"-{o}"] = (lambda oo: lambda s: s.endswith("__" + oo))(o)
    L = ["# Phase II results: function classifier and ablation (frozen held-out set)", "",
         f"Command: `python eval/phase2_ml.py`. Models trained on the development set only "
         f"({X.shape[0]} functions, {len(set(samples.tolist()))} images); k = {best_k} (min. functions per family), chosen by "
         "leave-one-optimisation-level-out CV on development data. Held-out: 32 images, tag `heldout-frozen-1`, "
         "predicted once. wolfSSL is a library no training image contains.", "",
         "## Systems (micro-average over the 13 families; image-level presence)", "",
         "| System | " + " | ".join(groups) + " |", "|---|" + "---|" * len(groups)]
    for sname, pred in systems.items():
        row = []
        for g, fn in groups.items():
            tr = sel(fn)
            r = micro(tr, {s: pred[s] for s in tr})
            row.append(f"P {r['P']:.2f} R {r['R']:.2f} F1 {r['F1']:.2f}")
        L.append(f"| {sname} | " + " | ".join(row) + " |")
    L += ["", "Counts (all 32, as frozen): " + "; ".join(
        f"{n}: TP {micro(htruth, p)['tp']} FP {micro(htruth, p)['fp']} FN {micro(htruth, p)['fn']}" for n, p in systems.items()),
        "", "Post-hoc (MD5 cells of the 16 mbedTLS images excluded because the frozen truth overstates them, see "
        "`results/heldout/ANALYSIS.md`): " + "; ".join(
            f"{n}: P {micro(htruth, p, md5_excl)['P']:.3f} R {micro(htruth, p, md5_excl)['R']:.3f} "
            f"F1 {micro(htruth, p, md5_excl)['F1']:.3f}" for n, p in systems.items()),
        "", "## Per family, all 32 images (TP / FP / FN)", "",
        "| Family | n true | " + " | ".join(systems) + " |", "|---|---|" + "---|" * len(systems)]
    pf = {n: per_family(htruth, p) for n, p in systems.items()}
    for f in SCORED_FAMILIES:
        n_true = sum(1 for s in htruth if f in htruth[s])
        L.append(f"| {f} | {n_true} | " + " | ".join("{}/{}/{}".format(*pf[n][f]) for n in systems) + " |")
    L += ["", "## Development cross-validation (leave one optimisation level out; ins+const)", "",
          f"Function-level accuracy {res['dev_cv_function_accuracy']:.3f}. Image-level micro F1 by k: " +
          ", ".join(f"k={k}: {v['F1']:.3f}" for k, v in sweep.items()) + f". Chosen k = {best_k}."]
    (OUT / "RESULTS_phase2.md").write_text("\n".join(L) + "\n")
    (OUT / "heldout_systems.json").write_text(json.dumps({n: {s: sorted(v) for s, v in p.items()} for n, p in systems.items()}, indent=1))
    print("\n".join(L), flush=True)
    print(f"done in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()

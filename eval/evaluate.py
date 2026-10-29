#!/usr/bin/env python3
"""Evaluate cbomscan against dataset ground truth.

Image-level family detection: for every firmware image the scanner reports the set of
algorithm families it believes are present; truth is the set of families whose code is
linked into the image (from the linker map). Reports precision/recall/F1 per family,
by optimisation level and library variant, against a strings-only baseline and
rule-group ablations. Secure Boot V2 signature blocks are scored separately.
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from cbomscan.image import load  # noqa: E402
from cbomscan.detect import scan, present_families, ALL_GROUPS  # noqa: E402
from cbomscan.taxonomy import SCORED_FAMILIES, PK_CLASSES, pk_class_of  # noqa: E402
import baseline_strings  # noqa: E402

SYSTEMS = {
    "strings-baseline": None,
    "rules:constants": ["constants"],
    "rules:constants+oid": ["constants", "oid"],
    "rules:constants+oid+keys": ["constants", "oid", "keys"],
    "rules:no-names": ["constants", "oid", "keys", "strings", "hw"],
    "rules:all": ["constants", "oid", "keys", "strings", "names", "hw"],
}
PRIMARY = "rules:all"


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


class Counter:
    def __init__(self):
        self.c = defaultdict(lambda: [0, 0, 0, 0])

    def add(self, key, truth, pred):
        t = self.c[key]
        if truth and pred:
            t[0] += 1
        elif pred and not truth:
            t[1] += 1
        elif truth and not pred:
            t[2] += 1
        else:
            t[3] += 1

    def metrics(self, key):
        tp, fp, fn, tn = self.c[key]
        p, r, f = prf(tp, fp, fn)
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r, "f1": f}

    def micro(self, keys):
        tp = sum(self.c[k][0] for k in keys)
        fp = sum(self.c[k][1] for k in keys)
        fn = sum(self.c[k][2] for k in keys)
        tn = sum(self.c[k][3] for k in keys)
        p, r, f = prf(tp, fp, fn)
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r, "f1": f}


def pk_classes(fams):
    return {pk_class_of(f) for f in fams if pk_class_of(f)}


def in_ranges(addr, ranges):
    return any(r["start"] <= addr < r["end"] for r in ranges)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=str(ROOT / "dataset/out"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    args = ap.parse_args()
    ds = Path(args.dataset)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    index = json.loads((ds / "index.json").read_text())
    code_samples = [s for s in index if s["secure_boot"] == "none"]
    signed = [s for s in index if s["secure_boot"] != "none"]

    counters = {name: {"family": Counter(), "opt": Counter(), "variant": Counter(), "pkclass": Counter(),
                       "image_qv": Counter()} for name in SYSTEMS}
    per_sample = []
    loc = defaultdict(lambda: defaultdict(int))
    timings = []
    for s in code_samples:
        sdir = ds / "samples" / s["sample"]
        truth = json.loads((sdir / "truth.json").read_text())
        tf = set(truth["present_families"])
        binf = sdir / "firmware.bin"
        fw = load(binf)
        row = {"sample": s["sample"], "variant": s["variant"], "opt": s["opt"], "profile": s["profile"],
               "truth": sorted(tf)}
        for name, groups in SYSTEMS.items():
            if groups is None:
                pf, _ = baseline_strings.detect(binf.read_bytes())
            else:
                t0 = time.perf_counter()
                res = scan(fw, groups=groups)
                dt = time.perf_counter() - t0
                if name == PRIMARY:
                    timings.append(dt)
                    for e in res.evidence:
                        if e.address is None:
                            continue
                        rng = truth["family_ranges"].get(e.family, [])
                        if e.family == "ECC":
                            rng = rng + truth["family_ranges"].get("ECDSA", []) + truth["family_ranges"].get("ECDH", [])
                        if in_ranges(e.address, rng):
                            where = "same-family object"
                        elif any(in_ranges(e.address, v) for v in truth["support_ranges"].values()):
                            where = "crypto support object (OID/PK/MD tables)"
                        elif any(in_ranges(e.address, v) for v in truth["family_ranges"].values()):
                            where = "other crypto object"
                        else:
                            where = "application / other"
                        loc[e.group][where] += 1
                pf = present_families(res)
            row[name] = sorted(pf)
            c = counters[name]
            for fam in SCORED_FAMILIES:
                c["family"].add(fam, fam in tf, fam in pf)
                c["opt"].add((s["opt"], fam), fam in tf, fam in pf)
                c["variant"].add((s["variant"], fam), fam in tf, fam in pf)
            tc, pc = pk_classes(tf), pk_classes(pf)
            for k in PK_CLASSES:
                c["pkclass"].add(k, k in tc, k in pc)
            c["image_qv"].add("any", bool(tc), bool(pc))
        per_sample.append(row)

    sb_rows = []
    for s in signed:
        sdir = ds / "samples" / s["sample"]
        fw = load(sdir / "firmware.bin")
        res = scan(fw)
        sbk = [k for k in res.keys if k.source == "secure-boot-v2"]
        exp = {"sbv2_rsa3072": ("RSA", 3072, "PSS"), "sbv2_ecdsa_p256": ("ECDSA", 256, "P-256")}[s["secure_boot"]]
        got = (sbk[0].algorithm, sbk[0].bits, sbk[0].param) if sbk else None
        sb_rows.append({"sample": s["sample"], "expected": exp, "got": got, "correct": got == exp,
                        "crc_ok": bool(sbk and "CRC ok" in sbk[0].context)})

    summary = {"dataset": {"code_samples": len(code_samples), "signed_samples": len(signed),
                           "variants": sorted({s["variant"] for s in index}), "opts": sorted({s["opt"] for s in index}),
                           "profiles": sorted({s["profile"] for s in index})},
               "systems": {}, "secure_boot": {"total": len(sb_rows), "correct": sum(r["correct"] for r in sb_rows),
                                              "rows": sb_rows},
               "localisation": {g: dict(v) for g, v in loc.items()},
               "scan_time_s": {"mean": sum(timings) / len(timings), "max": max(timings)}}
    for name in SYSTEMS:
        c = counters[name]
        sysd = {"micro": c["family"].micro(SCORED_FAMILIES),
                "per_family": {f: c["family"].metrics(f) for f in SCORED_FAMILIES},
                "per_opt": {o: c["opt"].micro([(o, f) for f in SCORED_FAMILIES]) for o in summary["dataset"]["opts"]},
                "per_variant": {v: c["variant"].micro([(v, f) for f in SCORED_FAMILIES])
                                for v in summary["dataset"]["variants"]},
                "per_opt_family": {o: {f: c["opt"].metrics((o, f)) for f in SCORED_FAMILIES}
                                   for o in summary["dataset"]["opts"]},
                "per_variant_family": {v: {f: c["variant"].metrics((v, f)) for f in SCORED_FAMILIES}
                                       for v in summary["dataset"]["variants"]},
                "pk_class": {k: c["pkclass"].metrics(k) for k in PK_CLASSES},
                "image_quantum_vulnerable": c["image_qv"].metrics("any")}
        summary["systems"][name] = sysd
    (out / "metrics.json").write_text(json.dumps(summary, indent=1))
    (out / "per_sample.json").write_text(json.dumps(per_sample, indent=1))
    write_markdown(summary, out)
    print((out / "RESULTS.md").read_text())


def fmt(x):
    return f"{x:.2f}"


def write_markdown(m, out):
    L = []
    d = m["dataset"]
    L.append("# Phase I evaluation results\n")
    L.append(f"Dataset: {d['code_samples']} unsigned firmware images ({len(d['variants'])} library variants x "
             f"{len(d['opts'])} optimisation levels x {len(d['profiles'])} profiles) plus {d['signed_samples']} "
             "Secure Boot V2 signed copies. Truth is the set of algorithm families whose code is linked into each "
             "image, taken from the linker map. Scores are image-level family detection, micro-averaged over 13 "
             "families unless stated.\n")
    L.append("## Systems compared\n")
    L.append("| System | Precision | Recall | F1 | TP | FP | FN |")
    L.append("|---|---|---|---|---|---|---|")
    for name, s in m["systems"].items():
        x = s["micro"]
        L.append(f"| {name} | {fmt(x['precision'])} | {fmt(x['recall'])} | {fmt(x['f1'])} | {x['tp']} | {x['fp']} | {x['fn']} |")
    p = m["systems"][PRIMARY]
    L.append(f"\n## Per family ({PRIMARY})\n")
    L.append("| Family | Precision | Recall | F1 | TP | FP | FN | TN |")
    L.append("|---|---|---|---|---|---|---|---|")
    for f, x in p["per_family"].items():
        L.append(f"| {f} | {fmt(x['precision'])} | {fmt(x['recall'])} | {fmt(x['f1'])} | {x['tp']} | {x['fp']} | {x['fn']} | {x['tn']} |")
    b = m["systems"]["strings-baseline"]
    L.append("\n## Per family: strings baseline vs rules (F1)\n")
    L.append("| Family | strings-baseline | rules:all |")
    L.append("|---|---|---|")
    for f in p["per_family"]:
        L.append(f"| {f} | {fmt(b['per_family'][f]['f1'])} | {fmt(p['per_family'][f]['f1'])} |")
    L.append(f"\n## By optimisation level ({PRIMARY})\n")
    L.append("| Opt | Precision | Recall | F1 |")
    L.append("|---|---|---|---|")
    for o, x in p["per_opt"].items():
        L.append(f"| {o} | {fmt(x['precision'])} | {fmt(x['recall'])} | {fmt(x['f1'])} |")
    L.append(f"\n## By library variant ({PRIMARY})\n")
    L.append("| Variant | Precision | Recall | F1 |")
    L.append("|---|---|---|---|")
    for v, x in p["per_variant"].items():
        L.append(f"| {v} | {fmt(x['precision'])} | {fmt(x['recall'])} | {fmt(x['f1'])} |")
    L.append("\n## Quantum-vulnerable public-key classes\n")
    L.append("| Class | strings P/R | rules:all P/R |")
    L.append("|---|---|---|")
    for k in p["pk_class"]:
        bx, px = b["pk_class"][k], p["pk_class"][k]
        L.append(f"| {k} | {fmt(bx['precision'])} / {fmt(bx['recall'])} | {fmt(px['precision'])} / {fmt(px['recall'])} |")
    q, qb = p["image_quantum_vulnerable"], b["image_quantum_vulnerable"]
    L.append(f"\nImage-level 'contains quantum-vulnerable public-key crypto': rules P={fmt(q['precision'])} "
             f"R={fmt(q['recall'])} (TP {q['tp']}, FP {q['fp']}, FN {q['fn']}, TN {q['tn']}); strings baseline "
             f"P={fmt(qb['precision'])} R={fmt(qb['recall'])}.\n")
    sb = m["secure_boot"]
    L.append(f"## Secure Boot V2 signature blocks\n\n{sb['correct']}/{sb['total']} signed images: scheme, key size and "
             "curve recovered correctly from the signature block.\n")
    L.append("## Where evidence addresses fall (rules:all)\n")
    L.append("| Rule group | Location | Evidence items |")
    L.append("|---|---|---|")
    for g, v in m["localisation"].items():
        for where, n in sorted(v.items(), key=lambda t: -t[1]):
            L.append(f"| {g} | {where} | {n} |")
    t = m["scan_time_s"]
    L.append(f"\nScan time per image: mean {t['mean'] * 1000:.0f} ms, max {t['max'] * 1000:.0f} ms (pure Python).\n")
    (out / "RESULTS.md").write_text("\n".join(L))


if __name__ == "__main__":
    main()

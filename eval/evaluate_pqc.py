#!/usr/bin/env python3
"""Evaluate the post-quantum rules (P2.9).

Positives: dataset/out_pqc (real reference implementations built with Espressif's Xtensa GCC).
Negatives: every Phase I image (no post-quantum code linked; 198 images).
Image-level detection per post-quantum family. These rules were derived from FIPS 203/204 and
checked on the same builds, so this is an in-distribution result, not a held-out one.
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cbomscan.detect import present_families, scan  # noqa: E402
from cbomscan.image import load  # noqa: E402
from cbomscan.taxonomy import PQC_FAMILIES  # noqa: E402


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    return p, r


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pqc", default=str(ROOT / "dataset/out_pqc"))
    ap.add_argument("--negatives", default=str(ROOT / "dataset/out"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()
    rows = []
    for base, kind in ((Path(a.pqc), "pqc"), (Path(a.negatives), "phase1")):
        for d in sorted((base / "samples").iterdir()):
            truth = json.loads((d / "truth.json").read_text())
            tf = set(truth["present_families"]) & set(PQC_FAMILIES)
            pf = present_families(scan(load(d / "firmware.bin")), families=PQC_FAMILIES)
            rows.append({"sample": d.name, "set": kind, "impl": truth.get("impl", "-"), "opt": truth["opt"],
                         "truth": sorted(tf), "pred": sorted(pf)})
    fams = [f for f in PQC_FAMILIES if any(f in r["truth"] for r in rows)]
    L = ["# Post-quantum rule evaluation (P2.9)", "",
         f"Positives: {sum(r['set'] == 'pqc' for r in rows)} images from real reference implementations built with "
         "Espressif xtensa-esp32-elf-gcc (windowed ABI). "
         f"Negatives: {sum(r['set'] == 'phase1' for r in rows)} Phase I images (no post-quantum code).", "",
         "In-distribution: rules were derived from FIPS 203/204 and verified on these same builds.", "",
         "| Family | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|"]
    metrics = {}
    for f in fams:
        tp = sum(f in r["truth"] and f in r["pred"] for r in rows)
        fp = sum(f not in r["truth"] and f in r["pred"] for r in rows)
        fn = sum(f in r["truth"] and f not in r["pred"] for r in rows)
        p, r_ = prf(tp, fp, fn)
        metrics[f] = {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r_}
        L.append(f"| {f} | {tp} | {fp} | {fn} | {p:.2f} | {r_:.2f} |")
    L += ["", "## Recall by implementation and optimisation level (positives only)", "",
          "| Implementation | " + " | ".join(sorted({r["opt"] for r in rows if r["set"] == "pqc"})) + " |",
          "|---|" + "---|" * len({r["opt"] for r in rows if r["set"] == "pqc"})]
    opts = sorted({r["opt"] for r in rows if r["set"] == "pqc"})
    by = defaultdict(dict)
    for r in rows:
        if r["set"] == "pqc":
            by[r["impl"]][r["opt"]] = "found" if r["truth"] == r["pred"] else "MISSED"
    for impl, d in sorted(by.items()):
        L.append(f"| {impl} | " + " | ".join(d.get(o, "-") for o in opts) + " |")
    out = Path(a.out)
    (out / "RESULTS_pqc.md").write_text("\n".join(L) + "\n")
    (out / "metrics_pqc.json").write_text(json.dumps({"families": metrics, "per_sample": rows}, indent=1))
    print("\n".join(L))


if __name__ == "__main__":
    main()

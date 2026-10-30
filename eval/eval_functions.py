#!/usr/bin/env python3
"""Evaluate function-start recovery (P2.4) against the unstripped ELF symbol table.

For each development sample: recover starts from firmware.bin (the scanner's input) and compare with the
STT_FUNC symbols (size > 0) of firmware.elf that lie in the image's code segments. Reports precision and
recall of start addresses, overall and per optimisation level.

  python eval/eval_functions.py [--dataset dataset/out_esp32] [--out results/functions]
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cbomscan import image  # noqa: E402
from cbomscan.functions import recover_functions  # noqa: E402


def elf_function_starts(elf_path):
    from elftools.elf.elffile import ELFFile
    with open(elf_path, "rb") as fh:
        f = ELFFile(fh)
        sec = f.get_section_by_name(".symtab")
        return {s["st_value"] for s in sec.iter_symbols()
                if s["st_info"]["type"] == "STT_FUNC" and s["st_size"] > 0}


def evaluate_sample(d):
    fw = image.load(str(d / "firmware.bin"))
    truth_all = elf_function_starts(d / "firmware.elf")
    code = [s for s in fw.segments if s.kind == "code"]
    truth = {a for a in truth_all if any(s.contains(a) for s in code)}
    found = {f.start for f in recover_functions(fw)}
    tp = len(truth & found)
    return {"truth": len(truth), "found": len(found), "tp": tp,
            "missed": sorted(truth - found), "false": sorted(found - truth)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(ROOT / "dataset" / "out_esp32"))
    ap.add_argument("--out", default=str(ROOT / "results" / "functions"))
    a = ap.parse_args()
    samples = sorted(p for p in (Path(a.dataset) / "samples").iterdir()
                     if (p / "firmware.elf").exists() and "__sbv2_" not in p.name)
    agg = defaultdict(lambda: {"truth": 0, "found": 0, "tp": 0, "n": 0})
    per = {}
    for d in samples:
        r = evaluate_sample(d)
        opt = re.search(r"__(O[0-3s])__", d.name).group(1)
        for key in ("all", opt):
            for k in ("truth", "found", "tp"):
                agg[key][k] += r[k]
            agg[key]["n"] += 1
        per[d.name] = {k: r[k] for k in ("truth", "found", "tp")} | {"n_missed": len(r["missed"]), "n_false": len(r["false"])}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for key in ["all", "O0", "O1", "O2", "O3", "Os"]:
        g = agg[key]
        p = g["tp"] / g["found"] if g["found"] else 0.0
        r = g["tp"] / g["truth"] if g["truth"] else 0.0
        rows.append((key, g["n"], g["truth"], g["found"], g["tp"], p, r))
    lines = ["# Function-start recovery (development images)", "",
             f"Command: `python eval/eval_functions.py --dataset {a.dataset}`. Truth: STT_FUNC symbols (size > 0) of the "
             "unstripped ELF inside the image's code segments. Signed (`__sbv2_`) copies are excluded (same code).", "",
             "| level | images | true starts | recovered | correct | precision | recall |", "|---|---|---|---|---|---|---|"]
    for key, n, t, f, tp, p, r in rows:
        lines.append(f"| {key} | {n} | {t} | {f} | {tp} | {p:.3f} | {r:.3f} |")
    (out / "RESULTS_functions.md").write_text("\n".join(lines) + "\n")
    (out / "metrics_functions.json").write_text(json.dumps({"summary": {k: agg[k] for k in agg}, "per_sample": per}, indent=1))
    print("\n".join(lines))


if __name__ == "__main__":
    main()

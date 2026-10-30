#!/usr/bin/env python3
"""Function-level labels for the development images (P2.5).

For every development sample, functions are *recovered from the stripped image* (cbomscan.functions, the same
code the scanner would run), and each is labelled from the linker-map truth by the address of its first byte:

  <FAMILY>   start lies in a code range attributed to one of the 13 scored families
  support    start lies in a support range (bignum, GCM, HKDF, DRBG, glue)
  other      anything else (application and non-crypto filler code)

Stripping does not move code, so the addresses in the unstripped build's map are the addresses in the image.
Output: dataset/functions/labels.jsonl.gz, one JSON object per recovered function.

  python dataset/make_function_labels.py [--dataset dataset/out_esp32] [--out dataset/functions/labels.jsonl.gz]
"""

import argparse
import bisect
import gzip
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cbomscan import image  # noqa: E402
from cbomscan.functions import recover_functions  # noqa: E402
from cbomscan.taxonomy import SCORED_FAMILIES  # noqa: E402


def build_index(truth):
    """Sorted (start, end, label) code ranges; scored families take precedence over support."""
    rng = []
    for fam, rs in truth["family_ranges"].items():
        if fam in SCORED_FAMILIES:
            rng += [(r["start"], r["end"], fam) for r in rs if r["kind"] == "code"]
    for grp, rs in (truth.get("support_ranges") or {}).items():
        rng += [(r["start"], r["end"], "support") for r in rs if r["kind"] == "code"]
    rng.sort()
    return rng


def label_at(rng, starts, addr):
    i = bisect.bisect_right(starts, addr) - 1
    # ranges may nest or touch; scan back a few entries for one that contains addr
    for j in range(i, max(i - 8, -1), -1):
        s, e, lab = rng[j]
        if s <= addr < e:
            return lab
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(ROOT / "dataset" / "out_esp32"))
    ap.add_argument("--out", default=str(ROOT / "dataset" / "functions" / "labels.jsonl.gz"))
    a = ap.parse_args()
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    counts, n_img = Counter(), 0
    with gzip.open(out, "wt", encoding="utf-8", newline="\n") as fh:
        for d in sorted((Path(a.dataset) / "samples").iterdir()):
            if "__sbv2_" in d.name or not (d / "firmware.bin").exists():
                continue
            truth = json.loads((d / "truth.json").read_text())
            rng = build_index(truth)
            starts = [r[0] for r in rng]
            fw = image.load(str(d / "firmware.bin"))
            m = re.match(r"(m\w+?)__(O[0-3s])__(.+)$", d.name)
            for f in recover_functions(fw):
                lab = label_at(rng, starts, f.start)
                counts[lab] += 1
                fh.write(json.dumps({"sample": d.name, "variant": m.group(1), "opt": m.group(2),
                                     "profile": m.group(3), "start": f.start, "end": f.end, "label": lab},
                                    separators=(",", ":")) + "\n")
            n_img += 1
    print(f"{n_img} images, {sum(counts.values())} functions -> {out}")
    for k, v in counts.most_common():
        print(f"  {k:10s} {v}")


if __name__ == "__main__":
    main()

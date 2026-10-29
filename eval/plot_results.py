#!/usr/bin/env python3
"""Render the per-family F1 comparison chart from results/metrics.json."""

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
S1 = "#2a78d6"
S2 = "#eb6834"

NAMES = {"AES": "AES", "DES": "DES/3DES", "CHACHA20": "ChaCha20", "POLY1305": "Poly1305", "MD5": "MD5",
         "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-384/512", "RSA": "RSA", "ECDSA": "ECDSA",
         "ECDH": "ECDH", "ECC": "EC arithmetic", "FFDH": "Finite-field DH"}


def main():
    res = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results"
    m = json.loads((res / "metrics.json").read_text())
    base = m["systems"]["strings-baseline"]["per_family"]
    rules = m["systems"]["rules:all"]["per_family"]
    fams = list(rules)[::-1]
    y = range(len(fams))
    h = 0.36
    fig, ax = plt.subplots(figsize=(8.2, 6.4), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    ax.barh([i + h / 2 + 0.01 for i in y], [rules[f]["f1"] for f in fams], height=h, color=S1,
            label="cbomscan rules (Phase I)")
    ax.barh([i - h / 2 - 0.01 for i in y], [base[f]["f1"] for f in fams], height=h, color=S2,
            label="Strings-only baseline")
    for i, f in enumerate(fams):
        r = rules[f]["f1"]
        if r < 0.9:
            ax.text(max(r, 0) + 0.015, i + h / 2, f"{r:.2f}", va="center", fontsize=8, color=INK2)
    ax.set_yticks(list(y))
    ax.set_yticklabels([NAMES[f] for f in fams], color=INK, fontsize=9)
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("F1 score (image-level family detection)", color=INK2, fontsize=9)
    ax.tick_params(axis="x", colors=INK2, labelsize=8)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ax.spines.values():
        s.set_visible(False)
    mr, mb = m["systems"]["rules:all"]["micro"], m["systems"]["strings-baseline"]["micro"]
    ax.set_title(f"Per-family F1 on {m['dataset']['code_samples']} stripped ESP32 images\n"
                 f"micro F1: rules {mr['f1']:.2f} (precision {mr['precision']:.2f}) vs strings "
                 f"{mb['f1']:.2f} (precision {mb['precision']:.2f})", loc="left", fontsize=10.5, color=INK)
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, -0.09), ncol=2, frameon=False, fontsize=8.5, labelcolor=INK2)
    fig.tight_layout()
    out = res / "f1_by_family.png"
    fig.savefig(out, facecolor=SURFACE)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

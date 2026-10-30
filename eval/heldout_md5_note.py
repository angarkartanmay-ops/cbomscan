#!/usr/bin/env python3
"""Post-hoc note on the frozen held-out baseline (results/heldout/ANALYSIS.md).

The frozen truth lists MD5 for the 16 ESP-IDF mbedTLS images because a 97-byte md5.c object is linked, but the
MD5 round constant K[0] = 0xd76aa478 is not in those images (MD5 runs from ROM). This script (a) verifies that
from the shipped images, and (b) recomputes the Rules:all micro-average with those 16 MD5 cells excluded.
The frozen truth is NOT changed; (b) is a secondary, post-hoc figure and is labelled as such.

  python eval/heldout_md5_note.py
"""
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELD = ROOT / "dataset" / "heldout"
K0 = struct.pack("<I", 0xD76AA478)
MBED = ("https_request", "simple_ota", "mqtt_ssl", "https_mbedtls")

ps = json.loads((ROOT / "results" / "heldout" / "per_sample.json").read_text())
fams = ["AES", "DES", "CHACHA20", "POLY1305", "MD5", "SHA1", "SHA256", "SHA512", "RSA", "ECDSA", "ECDH", "ECC", "FFDH"]


def micro(excl_md5_mbed):
    tp = fp = fn = 0
    for r in ps:
        t, p = set(r["truth"]), set(r["rules:all"])
        for f in fams:
            if f == "MD5" and excl_md5_mbed and r["profile"] in MBED:
                continue
            tp += f in t and f in p
            fp += f in p and f not in t
            fn += f in t and f not in p
    P, R = tp / (tp + fp), tp / (tp + fn)
    return tp, fp, fn, P, R, 2 * P * R / (P + R)


has = {r["sample"]: K0 in (HELD / "samples" / r["sample"] / "firmware.bin").read_bytes() for r in ps}
mb = [s for s in has if s.startswith(MBED)]
wo = [s for s in has if not s.startswith(MBED)]
print(f"MD5 K[0] present: mbedTLS images {sum(has[s] for s in mb)}/{len(mb)}, wolfSSL images {sum(has[s] for s in wo)}/{len(wo)}")
for name, ex in (("as frozen", False), ("post-hoc, MD5 cells of the 16 mbedTLS images excluded", True)):
    tp, fp, fn, P, R, F = micro(ex)
    print(f"{name}: TP {tp} FP {fp} FN {fn}  P {P:.3f} R {R:.3f} F1 {F:.3f}")

#!/usr/bin/env python3
"""Assemble dataset/heldout from the ESP-IDF build directories (P2.2) and optionally freeze it.

  python dataset/make_heldout.py [--builds C:/esp/build] [--out dataset/heldout] [--freeze]

Without --freeze it only assembles and prints the image list. With --freeze it also writes
MANIFEST.sha256 (SHA-256 of every file in the set); tests/test_heldout_frozen.py then fails on any change.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dataset"))
import heldout_truth  # noqa: E402

LEVELS = {"SIZE": "Os", "NONE": "O0", "DEBUG": "Og", "PERF": "O2"}
APPS = ["https_request", "simple_ota", "mqtt_ssl", "https_mbedtls",
        "wolf_wolfssl_client", "wolf_wolfssl_server", "wolf_wolfssl_test", "wolf_wolfssl_benchmark"]


def build_ok(builds, name):
    """True only when the build script's last log line says exit=0 (a failed size check still leaves a .bin)."""
    log = Path(builds) / f"{name}.log"
    if not log.exists():
        return False
    lines = log.read_bytes().decode("utf-16", errors="replace").strip().splitlines()
    return bool(lines) and lines[-1].startswith("exit=0")


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--builds", default="C:/esp/build")
    ap.add_argument("--out", default=str(ROOT / "dataset" / "heldout"))
    ap.add_argument("--freeze", action="store_true")
    a = ap.parse_args()
    out = Path(a.out)
    index, missing = [], []
    for app in APPS:
        for kc, lab in LEVELS.items():
            bd = Path(a.builds) / f"{app}__{kc}"
            if not build_ok(a.builds, f"{app}__{kc}") or not list(bd.glob("*.map")):
                missing.append(f"{app}__{kc}")
                continue
            t = heldout_truth.build_sample(bd, app, lab, out / "samples")
            index.append({k: t[k] for k in ("sample", "variant", "opt", "profile", "secure_boot",
                                            "present_families", "intended_families", "bin_size")})
    if missing:
        print("MISSING builds:", ", ".join(missing))
    (out / "index.json").write_text(json.dumps(index, indent=1))
    for r in index:
        print(f"{r['sample']:34s} {r['bin_size']:>8d} B  {','.join(r['present_families'])}")
    print(len(index), "images")
    if a.freeze:
        if missing:
            sys.exit("refusing to freeze with missing builds")
        files = sorted(p for p in out.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256")
        lines = [f"{sha(p)}  {p.relative_to(out).as_posix()}" for p in files]
        (out / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")
        print("wrote MANIFEST.sha256 with", len(lines), "entries")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Wrap an app image into a 4 MB flash dump (blank bootloader area, partition table at 0x8000,
factory app at 0x10000) so the flash-dump input path can be tested without hardware."""

import argparse
import hashlib
import struct
from pathlib import Path


def entry(label, ptype, subtype, offset, size):
    return struct.pack("<HBBII16sI", 0x50AA, ptype, subtype, offset, size, label.encode().ljust(16, b"\0"), 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("app")
    ap.add_argument("out")
    a = ap.parse_args()
    app = Path(a.app).read_bytes()
    flash = bytearray(b"\xff" * 0x400000)
    table = entry("nvs", 1, 2, 0x9000, 0x6000) + entry("phy_init", 1, 1, 0xF000, 0x1000) + \
        entry("factory", 0, 0, 0x10000, 0x100000)
    md5 = hashlib.md5(table).digest()
    table += b"\xeb\xeb" + b"\xff" * 14 + md5
    flash[0x8000:0x8000 + len(table)] = table
    flash[0x10000:0x10000 + len(app)] = app
    Path(a.out).write_bytes(bytes(flash))
    print(f"wrote {a.out}: app {len(app)} bytes at 0x10000")


if __name__ == "__main__":
    main()

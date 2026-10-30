#!/usr/bin/env python3
"""Ground truth for the held-out set (P2.2) from linker maps of ESP-IDF builds.

The attribution rules below were fixed from object *names* in the IDF map, before any held-out image was
scanned (docs/HELDOUT.md). Truth is linked capability: a family is present when any section of one of its
implementation objects survives linking. Glue and protocol layers (pk, oid, psa_crypto_*, libmbedtls, the
wpa_supplicant wrappers) are "support", exactly as in Phase I. Prebuilt Espressif blobs (libnet80211, libpp,
libphy, ...) cannot be attributed: this is a limitation of the truth, not a property of the scanner.

Usage: python dataset/heldout_truth.py <build-dir> <app name> <opt label> <out dir>
Produces <out dir>/<app>__<opt>/{firmware.bin, truth.json}; the map and ELF stay outside the repo.
"""

import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cbomscan.taxonomy import OBJECT_FAMILY, SCORED_FAMILIES  # noqa: E402

# mbedTLS (libmbedcrypto.a) objects: the shared Phase I table, plus ESP-IDF's hardware-driver ports.
IDF_PORT_FAMILY = {
    "esp_aes": "AES", "esp_aes_common": "AES", "esp_aes_gcm": "AES", "esp_aes_xts": "AES",
    "esp_sha1": "SHA1", "esp_sha256": "SHA256", "esp_sha512": "SHA512",
}
# Other crypto implementations inside IDF applications (names seen in the first IDF map).
OTHER_FAMILY = {"des-internal": "DES", "dh_groups": "FFDH"}
OBJ = re.compile(r"\(([^)]+?)(?:\.[cS])?\.obj\)$")
MAP_SECTION = re.compile(r"^ (\.[^\s]+|COMMON)(?:\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.+))?$")
MAP_CONT = re.compile(r"^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S.+)$")


# wolfSSL (libwolfssl.a) objects are monolithic: whole-file mapping only where one file is one family.
# ecc.c holds ECC, ECDSA and ECDH, so those are split by the function section name. Glue, bignum, the esp32_*
# hardware drivers, asn/ssl/tls, hmac, ed25519 and curve25519 are support or unscored, as in Phase I.
WOLF_OBJECT_FAMILY = {"aes": "AES", "des3": "DES", "md5": "MD5", "sha": "SHA1", "sha256": "SHA256",
                      "sha512": "SHA512", "rsa": "RSA", "ecc": "ECC", "chacha": "CHACHA20",
                      "poly1305": "POLY1305", "dh": "FFDH"}
WOLF_ECC_SPLIT = (("wc_ecc_sign_hash", "ECDSA"), ("wc_ecc_verify_hash", "ECDSA"),
                  ("wc_ecc_shared_secret", "ECDH"))


def families_of(src, sec=""):
    """Families for an input section (object path + section name) from the map; [] = support / unattributed."""
    m = OBJ.search(src)
    if not m:
        return []
    stem = m.group(1)
    if "libmbedcrypto.a" in src:
        f = IDF_PORT_FAMILY.get(stem) or OBJECT_FAMILY.get(stem)
        return [f] if f else []
    if "libwpa_supplicant.a" in src:
        f = OTHER_FAMILY.get(stem)
        return [f] if f else []
    if "libwolfssl.a" in src:
        f = WOLF_OBJECT_FAMILY.get(stem)
        if not f:
            return []
        out = [f]
        if stem == "ecc":
            out += [fam for prefix, fam in WOLF_ECC_SPLIT if f".{prefix}" in sec]
        return out
    return []


def family_of(src):
    """Single family (mbedTLS / wpa_supplicant objects); kept for callers that only need one."""
    f = families_of(src)
    return f[0] if f else None


def map_ranges(mapfile):
    lines = Path(mapfile).read_text(errors="replace").splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("Linker script and memory map"))
    out, pending = [], None
    for line in lines[start:]:
        if pending is not None:
            m = MAP_CONT.match(line)
            if m:
                out.append((pending, int(m.group(1), 16), int(m.group(2), 16), m.group(3).strip()))
            pending = None
            continue
        m = MAP_SECTION.match(line)
        if not m:
            continue
        if m.group(2) is None:
            pending = m.group(1)
        else:
            out.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16), m.group(4).strip()))
    return out


def extract_truth(mapfile):
    fam_ranges, other = {}, 0
    for sec, addr, size, src in map_ranges(mapfile):
        if size == 0 or addr == 0 or sec.startswith(".debug") or sec.startswith(".xt"):
            continue
        fams = families_of(src, sec)
        if not fams:
            other += size
            continue
        kind = "code" if (sec.startswith(".text") or sec.startswith(".literal") or sec.startswith(".iram")
                          or sec.startswith(".flash.text")) else "data"
        for fam in fams:
            fam_ranges.setdefault(fam, []).append({"start": addr, "end": addr + size, "section": sec,
                                                   "object": OBJ.search(src).group(1), "kind": kind})
    present = [f for f in SCORED_FAMILIES if f in fam_ranges]
    if any(f in present for f in ("ECDSA", "ECDH")) and "ECC" not in present:
        present.append("ECC")
    return {"present_families": present, "family_ranges": fam_ranges,
            "family_code_bytes": {f: sum(r["end"] - r["start"] for r in v if r["kind"] == "code")
                                  for f, v in fam_ranges.items()},
            "support_ranges": {}}


def build_sample(build, app, opt, out):
    """Copy the app image and write truth.json for one IDF build directory; returns the truth dict."""
    build = Path(build)
    sample = f"{app}__{opt}"
    d = Path(out) / sample
    d.mkdir(parents=True, exist_ok=True)
    binf = next(p for p in build.glob("*.bin") if p.stem not in ("bootloader", "partition-table", "ota_data_initial")
                and "bootloader" not in str(p))
    shutil.copy2(binf, d / "firmware.bin")
    truth = extract_truth(next(build.glob("*.map")))
    cfg = (build / "config" / "sdkconfig.h").read_text()
    truth.update({"sample": sample, "app": app, "opt": opt, "variant": ("wolfssl-v5.9.4-on-esp-idf-v5.5.6" if app.startswith("wolf_") else "esp-idf-v5.5.6"), "profile": app,
                  "secure_boot": "none", "build_system": "esp-idf v5.5.6 (cmake)",
                  "toolchain": "xtensa-esp-elf esp-14.2.0_20260121 (GCC 14.2.0), from ESP-IDF tools",
                  "intended_families": [], "sdkconfig_optimization": re.findall(r"CONFIG_COMPILER_OPTIMIZATION_(\w+) 1", cfg),
                  "bin_sha256": hashlib.sha256((d / "firmware.bin").read_bytes()).hexdigest(),
                  "bin_size": (d / "firmware.bin").stat().st_size})
    (d / "truth.json").write_text(json.dumps(truth, indent=1))
    return truth


def main():
    build, app, opt, out = sys.argv[1:5]
    truth = build_sample(build, app, opt, out)
    print(f"{truth['sample']}: {truth['bin_size']} B  {','.join(truth['present_families']) or '-'}")


if __name__ == "__main__":
    main()

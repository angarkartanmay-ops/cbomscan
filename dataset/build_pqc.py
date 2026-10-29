#!/usr/bin/env python3
"""Build reference post-quantum firmware images (P2.9) with Espressif's Xtensa GCC.

Each sample links one real reference implementation (PQClean or mlkem-native / mldsa-native),
a tiny app that calls it, and the same ESP32 startup / linker script as the Phase I dataset.
Output per sample (under dataset/out_pqc/samples/<impl>__<opt>/):
  firmware.elf, firmware.map, firmware.stripped.elf   rebuild only (not committed)
  firmware.bin                                         ESP32 app image (scanner input)
  truth.json                                           ground truth + the real NTT table bytes' location

Ground truth is the set of post-quantum families whose code is linked, taken from the linker map
(every object of the implementation is attributed to its family). `reference_tables` records the
symbol, address and size of the NTT zeta table in the unstripped ELF, so tests can compare the
spec-derived tables against the bytes of the shipped firmware.bin without needing the ELF.

Usage (toolchain on PATH, third_party/ populated):
    python dataset/build_pqc.py --toolchain-prefix xtensa-esp32-elf-
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DS = ROOT / "dataset"
TP = ROOT / "third_party"
SUP = DS / "support"

OPTS = {"O0": "-O0", "O1": "-O1", "O2": "-O2", "Os": "-Os", "O3": "-O3"}

PQC_COMMON = TP / "PQClean/common"
HS = TP / "hash-sigs"
HS_VERIFY = ["hss_verify", "hss_verify_inc", "hss_common", "hss_thread_single", "hss_zeroize", "lm_common",
             "lm_ots_common", "lm_ots_verify", "lm_verify", "endian", "hash", "sha256"]


MBED = TP / "mbedtls-3.6.7"


def _hashsigs(label, defs):
    # SHA-256 comes from mbedTLS through hash-sigs' EXT_SHA256_H hook (its default needs OpenSSL).
    return {"family": "LMS", "label": label, "src": [HS / f"{n}.c" for n in HS_VERIFY],
            "common": [MBED / "library/sha256.c", MBED / "library/platform_util.c"],
            "inc": [HS, SUP / "pqc", MBED / "include", MBED / "library"],
            "defs": defs + ['-DEXT_SHA256_H="ext_sha256.h"',
                            f'-DMBEDTLS_CONFIG_FILE="{(DS / "configs/mbedtls_36_config.h").as_posix()}"'],
            "main": SUP / "pqc/main_hashsigs.c", "stubs": [], "also_linked": ["SHA256"]}


IMPLS = {
    "pqclean_mlkem768": {
        "family": "MLKEM", "label": "PQClean ML-KEM-768 (clean C)",
        "src": sorted((TP / "PQClean/crypto_kem/ml-kem-768/clean").glob("*.c")),
        "common": [PQC_COMMON / "fips202.c"], "inc": [TP / "PQClean/crypto_kem/ml-kem-768/clean", PQC_COMMON],
        "defs": [], "main": SUP / "pqc/main_pqclean_mlkem768.c", "stubs": [SUP / "pqc/pqc_stubs.c"],
    },
    "pqclean_mldsa65": {
        "family": "MLDSA", "label": "PQClean ML-DSA-65 (clean C)",
        "src": sorted((TP / "PQClean/crypto_sign/ml-dsa-65/clean").glob("*.c")),
        "common": [PQC_COMMON / "fips202.c"], "inc": [TP / "PQClean/crypto_sign/ml-dsa-65/clean", PQC_COMMON],
        "defs": [], "main": SUP / "pqc/main_pqclean_mldsa65.c", "stubs": [SUP / "pqc/pqc_stubs.c"],
    },
    "mlkem_native768": {
        "family": "MLKEM", "label": "mlkem-native ML-KEM-768 (C backend)",
        "src": [TP / "mlkem-native/mlkem/mlkem_native.c"], "common": [], "inc": [TP / "mlkem-native/mlkem"],
        "defs": ["-DMLK_CONFIG_PARAMETER_SET=768", "-DMLK_CONFIG_NO_RANDOMIZED_API"],
        "main": SUP / "pqc/main_mlkem_native768.c", "stubs": [],
    },
    "mldsa_native65": {
        "family": "MLDSA", "label": "mldsa-native ML-DSA-65 (C backend)",
        "src": [TP / "mldsa-native/mldsa/mldsa_native.c"], "common": [], "inc": [TP / "mldsa-native/mldsa"],
        "defs": ["-DMLD_CONFIG_PARAMETER_SET=65", "-DMLD_CONFIG_NO_RANDOMIZED_API"],
        "main": SUP / "pqc/main_mldsa_native65.c", "stubs": [],
    },
    # Cisco hash-sigs LMS/HSS verifier (RFC 8554), verify-only; key embedded in the image (one per parameter set)
    "hashsigs_h5_w8": _hashsigs("hash-sigs LMS verify, embedded key H5/W8", ["-DLMS_KEY=lms_pub_h5_w8"]),
    "hashsigs_h5_w1": _hashsigs("hash-sigs LMS verify, embedded key H5/W1", ["-DLMS_KEY=lms_pub_h5_w1"]),
    "hashsigs_h5_w2": _hashsigs("hash-sigs LMS verify, embedded key H5/W2", ["-DLMS_KEY=lms_pub_h5_w2"]),
    "hashsigs_h10_w4": _hashsigs("hash-sigs LMS verify, embedded key H10/W4", ["-DLMS_KEY=lms_pub_h10_w4"]),
    # same verifier, key read from flash at run time: NO key structure in the image (known blind spot of the rules)
    "hashsigs_nokey": _hashsigs("hash-sigs LMS verify, key read at run time (nothing embedded)", ["-DLMS_NOKEY"]),
}

TABLE_SIZES = {"MLKEM": 128 * 2, "MLDSA": 256 * 4, "LMS": 60}  # bytes: zeta table int16x128 / int32x256; HSS public key


def run(cmd, cwd=None):
    r = subprocess.run([str(c) for c in cmd], cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(map(str, cmd))}\n{r.stdout}\n{r.stderr}")
    return r.stdout + r.stderr


MAP_SECTION = re.compile(r"^ (\.[^\s]+|COMMON)(?:\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.+))?$")
MAP_CONT = re.compile(r"^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S.+)$")


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


def extract_truth(mapfile, family):
    """Attribute every linked section under .../<impl>/<opt>/impl/ to the implementation's family."""
    ranges = []
    for sec, addr, size, src in map_ranges(mapfile):
        if size == 0 or addr == 0 or sec.startswith(".debug") or sec.startswith(".xt"):
            continue
        if "/impl/" not in src.replace("\\", "/"):
            continue
        kind = "code" if (sec.startswith(".text") or sec.startswith(".literal")) else "data"
        ranges.append({"start": addr, "end": addr + size, "section": sec, "object": Path(src).stem, "kind": kind})
    code = sum(r["end"] - r["start"] for r in ranges if r["kind"] == "code")
    return {"present_families": [family] if ranges else [], "family_ranges": {family: ranges},
            "family_code_bytes": {family: code}}


def zeta_tables(elf_path, family):
    """Locate the NTT zeta table(s) in the unstripped ELF by symbol name and size."""
    from elftools.elf.elffile import ELFFile
    want = TABLE_SIZES[family]
    out = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        for sym in symtab.iter_symbols():
            is_ref = sym.name.startswith("lms_pub_") if family == "LMS" else "zeta" in sym.name.lower()
            if is_ref and sym["st_info"]["type"] == "STT_OBJECT" and sym["st_size"] == want:
                out.append({"symbol": sym.name, "address": sym["st_value"], "size": sym["st_size"]})
    return out


class Builder:
    def __init__(self, a):
        self.a = a
        self.cc = a.toolchain_prefix + "gcc"
        self.strip = a.toolchain_prefix + "strip"
        self.out = Path(a.out).resolve()

    def cflags(self, opt, impl):
        return ["-mlongcalls", "-ffunction-sections", "-fdata-sections", "-g", "-w", "-std=gnu11", "-DNDEBUG",
                OPTS[opt], *impl["defs"], *[f"-I{i}" for i in impl["inc"]]]

    def compile(self, src, obj, flags):
        obj.parent.mkdir(parents=True, exist_ok=True)
        if obj.exists() and obj.stat().st_mtime > Path(src).stat().st_mtime and not self.a.rebuild:
            return obj
        run([self.cc, *flags, "-c", src, "-o", obj])
        return obj

    def build(self, name, opt):
        impl = IMPLS[name]
        sample = f"{name}__{opt}"
        sdir = self.out / "samples" / sample
        sdir.mkdir(parents=True, exist_ok=True)
        odir = self.out / "_obj" / name / opt
        fl = self.cflags(opt, impl)
        objs = [self.compile(s, odir / "impl" / (s.stem + ".o"), fl) for s in impl["src"]]
        objs += [self.compile(s, odir / "common" / (s.stem + ".o"), fl) for s in impl["common"]]
        objs.append(self.compile(impl["main"], odir / "app" / "main.o", fl))
        for s in impl["stubs"]:
            objs.append(self.compile(s, odir / "app" / (s.stem + ".o"), fl))
        base = ["-mlongcalls", "-ffunction-sections", "-fdata-sections", "-g", "-w", "-std=gnu11", OPTS[opt]]
        objs.append(self.compile(SUP / "startup.c", odir / "app" / "startup.o", base))
        objs.append(self.compile(SUP / "app_desc.c", odir / "app" / "app_desc.o",
                                 base + [f'-DCBOM_PROJECT="{name[:31]}"']))
        elf, mapf = sdir / "firmware.elf", sdir / "firmware.map"
        run([self.cc, "-mlongcalls", f"-T{SUP / 'esp32_app.ld'}", "-nostartfiles", "-Wl,--gc-sections",
             f"-Wl,-Map={mapf}", "-Wl,--no-warn-rwx-segments",
             "-Wl,--defsym=end=__heap_start", *objs, "-o", elf,
             "-Wl,--start-group", "-lc", "-lgcc", "-Wl,--end-group"])
        stripped = sdir / "firmware.stripped.elf"
        run([self.strip, "--strip-all", "-o", stripped, elf])
        binf = sdir / "firmware.bin"
        run(["esptool", "--chip", "esp32", "elf2image", "--flash-size", "4MB", "-o", binf, stripped])
        truth = extract_truth(mapf, impl["family"])
        ver = run([self.cc, "--version"]).splitlines()[0]
        truth.update({"sample": sample, "impl": name, "impl_label": impl["label"], "opt": opt,
                      "secure_boot": "none", "toolchain": ver, "abi": "windowed",
                      "also_linked_unscored_here": impl.get("also_linked", []),
                      "reference_tables": zeta_tables(elf, impl["family"]),
                      "bin_sha256": hashlib.sha256(binf.read_bytes()).hexdigest(), "bin_size": binf.stat().st_size})
        (sdir / "truth.json").write_text(json.dumps(truth, indent=1))
        return truth


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--toolchain-prefix", default="xtensa-esp32-elf-")
    ap.add_argument("--out", default=str(DS / "out_pqc"))
    ap.add_argument("--impls", default=",".join(IMPLS))
    ap.add_argument("--opts", default=",".join(OPTS))
    ap.add_argument("--rebuild", action="store_true")
    a = ap.parse_args()
    b = Builder(a)
    for name in a.impls.split(","):
        for opt in a.opts.split(","):
            t = b.build(name, opt)
            tabs = ", ".join(f"{x['symbol']}@0x{x['address']:x}" for x in t["reference_tables"]) or "NO TABLE SYMBOL"
            print(f"built {t['sample']:28s} {t['bin_size']:>8d} B  {','.join(t['present_families']) or '-'}  [{tabs}]")
    index = []
    for tj in sorted((b.out / "samples").glob("*/truth.json")):   # index covers every sample on disk, not just this run
        t = json.loads(tj.read_text())
        index.append({k: t[k] for k in ("sample", "impl", "opt", "secure_boot", "present_families", "bin_size")})
    (b.out / "index.json").write_text(json.dumps(index, indent=1))
    print(f"{len(index)} samples -> {b.out / 'index.json'}")


if __name__ == "__main__":
    main()

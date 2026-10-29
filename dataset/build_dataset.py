#!/usr/bin/env python3
"""Build the labelled ESP32 firmware dataset.

For every (library variant, optimisation level, profile) it compiles mbedTLS plus
non-crypto filler (cJSON, miniz), links an app with an ESP32 memory map, and writes:
  firmware.elf          unstripped ELF with debug info (ground-truth source only)
  firmware.map          linker map, used to attribute every byte to an object file
  firmware.stripped.elf stripped ELF
  firmware.bin          ESP32 app image (scanner input)
  truth.json            families present, with address ranges per family
Optionally (Os builds) it also writes Secure Boot V2 signed copies.

The toolchain is configurable so the same script runs with Espressif's
xtensa-esp32-elf-gcc (windowed ABI) on a machine with ESP-IDF installed.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cbomscan.taxonomy import OBJECT_FAMILY, OBJECT_SUPPORT, SECTION_FAMILY_OVERRIDES, SCORED_FAMILIES  # noqa: E402

DS = ROOT / "dataset"
TP = ROOT / "third_party"

COMMON_MBEDTLS = ["aes", "des", "chacha20", "poly1305", "chachapoly", "gcm", "cipher", "cipher_wrap", "md",
                  "md5", "sha1", "sha256", "sha512", "hkdf", "ctr_drbg", "bignum", "rsa", "dhm", "ecp",
                  "ecp_curves", "ecdsa", "ecdh", "asn1parse", "asn1write", "oid", "pk", "pk_wrap", "pkparse",
                  "base64", "pem", "platform_util", "constant_time"]

VARIANTS = {
    "m36": {"src": TP / "mbedtls-3.6.7", "config": DS / "configs/mbedtls_36_config.h",
            "files": COMMON_MBEDTLS + ["bignum_core", "rsa_alt_helpers", "pk_ecc"], "defines": [],
            "label": "mbedTLS 3.6.7, AES tables generated at runtime"},
    "m36rom": {"src": TP / "mbedtls-3.6.7", "config": DS / "configs/mbedtls_36_config.h",
               "files": COMMON_MBEDTLS + ["bignum_core", "rsa_alt_helpers", "pk_ecc"],
               "defines": ["-DMBEDTLS_AES_ROM_TABLES"],
               "label": "mbedTLS 3.6.7, AES tables in flash (ROM tables)"},
    "m228": {"src": TP / "mbedtls-2.28.10", "config": DS / "configs/mbedtls_228_config.h",
             "files": COMMON_MBEDTLS + ["rsa_internal"], "defines": [],
             "label": "mbedTLS 2.28.10, AES tables generated at runtime"},
}

OPTS = {"O0": ["-O0"], "O1": ["-O1"], "O2": ["-O2"], "Os": ["-Os"], "O3": ["-O3"]}
PHASE1_OPTS = "O0,O1,O2,Os"   # default: the four levels of the Phase I dataset; pass --opts for -O3

PROFILES = {
    "ota_rsa_pss": {"intended": ["RSA", "SHA256"], "uses_hw": False},
    "ota_ecdsa_p256": {"intended": ["ECDSA", "SHA256"], "uses_hw": False},
    "tls_ecdhe_p256_gcm": {"intended": ["ECDH", "AES", "SHA256"], "uses_hw": False},
    "x25519_chachapoly": {"intended": ["ECDH", "CHACHA20", "POLY1305", "SHA512"], "uses_hw": False},
    "legacy_md5_sha1_3des_rsa": {"intended": ["MD5", "SHA1", "DES", "RSA"], "uses_hw": False},
    "ffdh_aes_cbc": {"intended": ["FFDH", "AES", "SHA1"], "uses_hw": False},
    "symmetric_only": {"intended": ["AES", "SHA256", "SHA512"], "uses_hw": False},
    "hwaccel_ecdsa_p384": {"intended": ["ECDSA", "SHA256", "AES"], "uses_hw": True},
    "noncrypto": {"intended": [], "uses_hw": False},
    "device_identity_rsa2048": {"intended": ["RSA", "SHA256"], "uses_hw": False},
    "full_stack": {"intended": ["RSA", "ECDSA", "ECDH", "FFDH", "AES", "DES", "CHACHA20", "POLY1305",
                                "MD5", "SHA1", "SHA256", "SHA512"], "uses_hw": True},
}

FULL_PARTS = {"ota_rsa_pss": "full_ota_rsa", "ota_ecdsa_p256": "full_ota_ecdsa",
              "tls_ecdhe_p256_gcm": "full_tls", "x25519_chachapoly": "full_x25519",
              "legacy_md5_sha1_3des_rsa": "full_legacy", "ffdh_aes_cbc": "full_ffdh",
              "symmetric_only": "full_sym", "hwaccel_ecdsa_p384": "full_hw"}


def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(map(str, cmd))}\n{r.stdout}\n{r.stderr}")
    return r.stdout


class Builder:
    def __init__(self, args):
        self.args = args
        self.prefix = args.toolchain_prefix
        self.cc = self.prefix + "gcc"
        self.strip = self.prefix + "strip"
        self.specs = args.specs
        self.out = Path(args.out).resolve()
        self.obj = self.out / "_obj"

    def compiler_version(self):
        if not hasattr(self, "_ver"):
            self._ver = run([self.cc, "--version"]).splitlines()[0]
        return self._ver

    def base_cflags(self, opt):
        f = ["-mlongcalls", "-ffunction-sections", "-fdata-sections", "-g", "-w", "-std=gnu11", "-DNDEBUG"]
        if self.specs:
            f.append(f"--specs={self.specs}")
        f += OPTS[opt]
        f += [f"-I{DS / 'support/include'}", f"-I{TP / 'jsmn'}", f"-I{TP / 'mprintf'}", f"-I{TP / 'miniz'}"]
        return f

    def compile(self, src, obj, flags):
        obj.parent.mkdir(parents=True, exist_ok=True)
        if obj.exists() and obj.stat().st_mtime > Path(src).stat().st_mtime and not self.args.rebuild:
            return obj
        run([self.cc, *flags, "-c", str(src), "-o", str(obj)])
        return obj

    def mbedtls_flags(self, variant, opt):
        v = VARIANTS[variant]
        return self.base_cflags(opt) + [f"-I{v['src'] / 'include'}", f"-I{v['src'] / 'library'}",
                                        f'-DMBEDTLS_CONFIG_FILE="{v["config"]}"', *v["defines"]]

    def build_libs(self, variant, opt):
        v = VARIANTS[variant]
        odir = self.obj / variant / opt
        flags = self.mbedtls_flags(variant, opt)
        objs = []
        for f in v["files"]:
            objs.append(self.compile(v["src"] / "library" / f"{f}.c", odir / "mbedtls" / f"{f}.o", flags))
        base = self.base_cflags(opt)
        neg = base + ["-DMINIZ_NO_STDIO", "-DMINIZ_NO_TIME", "-DMINIZ_NO_ARCHIVE_APIS", "-DMINIZ_NO_ZLIB_COMPATIBLE_NAMES"]
        objs.append(self.compile(TP / "mprintf/printf.c", odir / "filler" / "printf.o",
                                 base + ["-DPRINTF_DISABLE_SUPPORT_FLOAT", "-DPRINTF_DISABLE_SUPPORT_EXPONENTIAL"]))
        objs.append(self.compile(DS / "support/libgcc_shim.c", odir / "support" / "libgcc_shim.o", base))
        for m in ["miniz", "miniz_tdef", "miniz_tinfl"]:
            objs.append(self.compile(TP / f"miniz/{m}.c", odir / "filler" / f"{m}.o", neg))
        objs.append(self.compile(DS / "support/app_common.c", odir / "support" / "app_common.o", flags + ["-DMINIZ_NO_STDIO"]))
        objs.append(self.compile(DS / "support/startup.c", odir / "support" / "startup.o", base))
        objs.append(self.compile(DS / "support/hw_crypto_esp32.c", odir / "support" / "hw_crypto_esp32.o", base))
        return objs

    def profile_objs(self, variant, opt, profile):
        odir = self.obj / variant / opt / "profile"
        flags = self.mbedtls_flags(variant, opt) + [f"-I{DS / 'support/keys'}"]
        if profile != "full_stack":
            return [self.compile(DS / "profiles" / f"{profile}.c", odir / f"{profile}.o", flags)]
        objs = [self.compile(DS / "profiles/full_stack.c", odir / "full_stack.o", flags)]
        for part, sym in FULL_PARTS.items():
            objs.append(self.compile(DS / "profiles" / f"{part}.c", odir / f"full__{part}.o",
                                     flags + [f"-Dapp_main={sym}", f"-Ds_image=s_image_{sym}", f"-Ds_sig=s_sig_{sym}",
                                              f"-Ds_csr=s_csr_{sym}", f"-Ds_p=s_p_{sym}", f"-Ds_g=s_g_{sym}"]))
        return objs

    def link(self, variant, opt, profile, lib_objs):
        sample = f"{variant}__{opt}__{profile}"
        sdir = self.out / "samples" / sample
        sdir.mkdir(parents=True, exist_ok=True)
        desc = self.compile(DS / "support/app_desc.c", self.obj / variant / opt / "desc" / f"{profile}.o",
                            self.base_cflags(opt) + [f'-DCBOM_PROJECT="{profile[:31]}"'])
        objs = lib_objs + self.profile_objs(variant, opt, profile) + [desc]
        elf = sdir / "firmware.elf"
        mapf = sdir / "firmware.map"
        ldflags = [f"-T{DS / 'support/esp32_app.ld'}", "-nostartfiles", "-Wl,--gc-sections",
                   f"-Wl,-Map={mapf}", "-Wl,--no-warn-rwx-segments"]
        if self.specs:
            ldflags.insert(0, f"--specs={self.specs}")
        ldflags += self.args.ld_extra.split()
        run([self.cc, "-mlongcalls", *ldflags, *map(str, objs), "-o", str(elf),
             "-Wl,--start-group", "-lc", "-lgcc", "-Wl,--end-group"])
        stripped = sdir / "firmware.stripped.elf"
        run([self.strip, "--strip-all", "-o", str(stripped), str(elf)])
        binf = sdir / "firmware.bin"
        run(["esptool", "--chip", "esp32", "elf2image", "--flash-size", "4MB", "-o", str(binf), str(stripped)])
        truth = extract_truth(mapf)
        truth.update({"sample": sample, "variant": variant, "variant_label": VARIANTS[variant]["label"],
                      "opt": opt, "profile": profile, "intended_families": PROFILES[profile]["intended"],
                      "uses_hw_accel": PROFILES[profile]["uses_hw"], "secure_boot": "none",
                      "toolchain": self.prefix.rstrip("-"), "compiler": self.compiler_version(),
                      "bin_sha256": hashlib.sha256(binf.read_bytes()).hexdigest(),
                      "bin_size": binf.stat().st_size})
        (sdir / "truth.json").write_text(json.dumps(truth, indent=1))
        out = [truth]
        if opt == "Os" and self.args.sign:
            out += self.sign_variants(sdir, binf, truth)
        return out

    def sign_variants(self, sdir, binf, truth):
        res = []
        keys = {"sbv2_rsa3072": self.out / "_keys" / "sb_rsa3072.pem",
                "sbv2_ecdsa_p256": self.out / "_keys" / "sb_ecdsa_p256.pem"}
        for name, key in keys.items():
            sample = truth["sample"] + "__" + name
            ddir = self.out / "samples" / sample
            ddir.mkdir(parents=True, exist_ok=True)
            signed = ddir / "firmware.bin"
            run(["espsecure", "sign-data", "--version", "2", "--keyfile", str(key), "--output", str(signed), str(binf)])
            for f in ["firmware.map", "firmware.elf"]:
                shutil.copy2(sdir / f, ddir / f)
            t = dict(truth)
            t.update({"sample": sample, "secure_boot": name,
                      "bin_sha256": hashlib.sha256(signed.read_bytes()).hexdigest(), "bin_size": signed.stat().st_size})
            (ddir / "truth.json").write_text(json.dumps(t, indent=1))
            res.append(t)
        return res


MAP_SECTION = re.compile(r"^ (\.[^\s]+|COMMON)(?:\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(.+))?$")
MAP_CONT = re.compile(r"^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S.+)$")


def object_key(path):
    m = re.search(r"\(([^)]+)\.o\)$", path)
    if m:
        return "libc:" + m.group(1)
    return Path(path).stem


def family_for(objkey, section):
    for frag, fam in SECTION_FAMILY_OVERRIDES:
        if frag in section:
            return fam
    if objkey in OBJECT_FAMILY:
        return OBJECT_FAMILY[objkey]
    if objkey in OBJECT_SUPPORT:
        return "support:" + OBJECT_SUPPORT[objkey]
    return None


def extract_truth(mapfile):
    lines = Path(mapfile).read_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("Linker script and memory map"))
    ranges = []
    pending = None
    for line in lines[start:]:
        if pending is not None:
            m = MAP_CONT.match(line)
            if m:
                ranges.append((pending, int(m.group(1), 16), int(m.group(2), 16), m.group(3).strip()))
            pending = None
            continue
        m = MAP_SECTION.match(line)
        if not m:
            continue
        if m.group(2) is None:
            pending = m.group(1)
        else:
            ranges.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16), m.group(4).strip()))
    fam_ranges = {}
    support = {}
    for sec, addr, size, src in ranges:
        if size == 0 or addr == 0 or sec.startswith(".debug") or sec.startswith(".xt"):
            continue
        key = object_key(src)
        fam = family_for(key, sec)
        if fam is None:
            continue
        kind = "code" if (sec.startswith(".text") or sec.startswith(".literal") or sec.startswith(".iram")) else "data"
        rec = {"start": addr, "end": addr + size, "section": sec, "object": key, "kind": kind}
        if fam.startswith("support:"):
            support.setdefault(fam.split(":", 1)[1], []).append(rec)
        else:
            fam_ranges.setdefault(fam, []).append(rec)
    present = [f for f in SCORED_FAMILIES if f in fam_ranges]
    if any(f in present for f in ("ECDSA", "ECDH")) and "ECC" not in present:
        present.append("ECC")
    code_bytes = {f: sum(r["end"] - r["start"] for r in fam_ranges[f] if r["kind"] == "code") for f in fam_ranges}
    return {"present_families": present, "family_code_bytes": code_bytes,
            "family_ranges": fam_ranges, "support_ranges": support}


def make_sign_keys(out):
    kd = out / "_keys"
    kd.mkdir(parents=True, exist_ok=True)
    rsa = kd / "sb_rsa3072.pem"
    ec = kd / "sb_ecdsa_p256.pem"
    if not rsa.exists():
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(rsa)])
    if not ec.exists():
        run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(ec)])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--toolchain-prefix", default=os.environ.get("CBOM_TOOLCHAIN", "xtensa-lx106-elf-"))
    ap.add_argument("--specs", default=os.environ.get("CBOM_SPECS", "/usr/lib/xtensa-lx106-elf/picolibc.specs"),
                    help="GCC specs for the C library; pass '' when the toolchain ships its own libc (ESP-IDF)")
    ap.add_argument("--ld-extra", default=os.environ.get("CBOM_LD_EXTRA", ""),
                    help="extra linker flags, e.g. '-Wl,--defsym=end=__heap_start' for newlib's sbrk (Espressif toolchain)")
    ap.add_argument("--out", default=str(DS / "out"))
    ap.add_argument("--variants", default=",".join(VARIANTS))
    ap.add_argument("--opts", default=PHASE1_OPTS, help=f"comma list from {','.join(OPTS)}")
    ap.add_argument("--profiles", default=",".join(PROFILES))
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--no-sign", dest="sign", action="store_false")
    ap.add_argument("--rebuild", action="store_true")
    args = ap.parse_args()

    b = Builder(args)
    b.out.mkdir(parents=True, exist_ok=True)
    if args.sign:
        make_sign_keys(b.out)
    variants = args.variants.split(",")
    opts = args.opts.split(",")
    profiles = args.profiles.split(",")

    def lib_job(vo):
        return vo, b.build_libs(*vo)

    combos = [(v, o) for v in variants for o in opts]
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        libs = dict(ex.map(lib_job, combos))

    def link_job(t):
        v, o, p = t
        return b.link(v, o, p, libs[(v, o)])

    jobs = [(v, o, p) for v, o in combos for p in profiles]
    index = []
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for res in ex.map(link_job, jobs):
            for t in res:
                index.append({k: t[k] for k in ("sample", "variant", "opt", "profile", "secure_boot",
                                                "present_families", "intended_families", "bin_size")})
                print(f"built {t['sample']:60s} {t['bin_size']:>8d} B  {','.join(t['present_families']) or '-'}")
    index.sort(key=lambda r: r["sample"])
    (b.out / "index.json").write_text(json.dumps(index, indent=1))
    print(f"{len(index)} samples -> {b.out / 'index.json'}")


if __name__ == "__main__":
    main()

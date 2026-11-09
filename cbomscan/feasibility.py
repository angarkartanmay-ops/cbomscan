"""Phase III (P3.1): can the post-quantum replacement fit on this device?

Static checks only. Each check says what it measured, what it assumed, and returns one of
ok / warn / blocked / unknown. Nothing here claims a migration will work; it says where the
image gives a reason to expect trouble.

Code sizes are measured from this project's own builds (Espressif GCC 16.1, -Os, single
library per image), recorded in dataset/out_pqc/samples/<name>/truth.json as the bytes of
code and read-only data attributed to the library. tests/test_feasibility.py re-derives them.
"""

import re

from .migration import ESP_PQC_SOURCE, PQC_COSTS

DEFAULT_APP_PARTITION = 0x100000

MEASURED = {
    "ML-KEM-768": {"bytes": 10585, "sample": "mlkem_native768__Os", "impl": "mlkem-native ML-KEM-768 (C backend)"},
    "ML-DSA-65": {"bytes": 14558, "sample": "mldsa_native65__Os", "impl": "mldsa-native ML-DSA-65 (C backend)"},
    "LMS-verify": {"bytes": 2055, "sample": "hashsigs_h10_w4__Os", "impl": "hash-sigs LMS verify (needs SHA-256)"},
}

XTENSA = {"ESP32", "ESP32-S2", "ESP32-S3"}
PQC_BOOT_CHIPS = {"ESP32-C3", "ESP32-C5", "ESP32-C6"}
FREE_MARGIN = 0.10

ACTIONS = [
    {"id": "signatures", "families": ["RSA", "ECDSA"],
     "title": "Move firmware and identity signatures to ML-DSA-65 (or LMS for firmware signing)"},
    {"id": "key-agreement", "families": ["ECDH", "FFDH", "ECC"],
     "title": "Move key agreement to hybrid X25519MLKEM768"},
    {"id": "weak-today", "families": ["MD5", "SHA1", "DES"],
     "title": "Replace MD5, SHA-1 and DES/3DES"},
    {"id": "aes-256", "families": ["AES"],
     "title": "Use 256-bit AES keys for long-lived secrets"},
]

RANK = {"ok": 0, "unknown": 1, "warn": 2, "blocked": 3}


def isa(chip):
    base = chip.split(" ")[0]
    if base in XTENSA:
        return "xtensa"
    if base.startswith("ESP32-") and base not in XTENSA:
        return "riscv"
    return "unknown"


def idf_major(fw):
    m = re.search(r"v?(\d+)\.(\d+)", (fw.app_desc or {}).get("idf_ver", "") or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def app_partition(fw):
    for p in fw.partitions:
        if p.get("offset") == fw.app_offset and p.get("type") == 0:
            return p["size"], f"app partition '{p['label']}' from the partition table"
    return DEFAULT_APP_PARTITION, "assumed 1 MB app partition (ESP-IDF default; no partition table in this input)"


def _check(name, status, detail, assumption=None):
    c = {"check": name, "status": status, "detail": detail}
    if assumption:
        c["assumption"] = assumption
    return c


def _flash(fw, need, what):
    size, source = app_partition(fw)
    used = fw.image_size
    after = used + need
    free_after = size - after
    if after > size:
        status = "blocked"
    elif free_after < size * FREE_MARGIN:
        status = "warn"
    else:
        status = "ok"
    detail = (f"image {used:,} B + about {need:,} B for {what} = {after:,} B of {size:,} B "
              f"({max(free_after, 0) * 100 // size}% free after)")
    return _check("Flash headroom", status, detail, source)


def _idf(fw):
    raw = (fw.app_desc or {}).get("idf_ver", "") or ""
    if raw.endswith("-sim"):
        return _check("ESP-IDF version", "unknown", f"version string '{raw}' is a placeholder written by this project's dataset builder",
                      "esp-pqc needs ESP-IDF v6.0 or later")
    v = idf_major(fw)
    if v is None:
        return _check("ESP-IDF version", "unknown", "no ESP-IDF version in the app descriptor",
                      "esp-pqc needs ESP-IDF v6.0 or later")
    if v[0] >= 6:
        return _check("ESP-IDF version", "ok", f"built with ESP-IDF v{v[0]}.{v[1]}; esp-pqc needs v6.0 or later")
    return _check("ESP-IDF version", "warn",
                  f"built with ESP-IDF v{v[0]}.{v[1]}; esp-pqc needs v6.0 or later, so the project must be upgraded first")


def assess(fw, present, signed=False):
    chip = fw.chip.split(" ")[0]
    out = []
    for a in ACTIONS:
        hit = [f for f in a["families"] if f in present]
        if a["id"] == "signatures" and signed and "secure-boot" not in hit:
            hit = hit + ["secure-boot"]
        checks = []
        if a["id"] == "signatures":
            m = MEASURED["ML-DSA-65"]
            c = PQC_COSTS["ML-DSA-65"]
            need = m["bytes"] + c["public_key_bytes"] + c["signature_bytes"]
            checks.append(_flash(fw, need, "ML-DSA-65 library code, public key and one signature"))
            checks[-1]["source"] = f"code size measured from {m['sample']}; key and signature sizes from FIPS 204"
            checks.append(_idf(fw))
            if signed:
                if chip in PQC_BOOT_CHIPS:
                    checks.append(_check("Post-quantum boot verification", "ok",
                                         f"esp-pqc hybrid Secure Boot supports {chip} (about 8 KB more flash and about 78 ms more boot time)"))
                else:
                    checks.append(_check("Post-quantum boot verification", "blocked",
                                         f"esp-pqc hybrid Secure Boot supports ESP32-C3, C5 and C6 only, not {chip}; "
                                         "on this chip ML-DSA can protect OTA updates in the application, not the boot chain"))
                checks.append(_check("ROM verifier", "warn",
                                     "the chip ROM checks the 2nd-stage bootloader with RSA or ECDSA and cannot be patched; "
                                     "hybrid boot keeps that classical step"))
        elif a["id"] == "key-agreement":
            m = MEASURED["ML-KEM-768"]
            checks.append(_flash(fw, m["bytes"], "ML-KEM-768 code"))
            checks[-1]["source"] = f"code size measured from {m['sample']}"
            checks.append(_idf(fw))
            k = PQC_COSTS["X25519MLKEM768"]
            checks.append(_check("RAM for TLS buffers", "unknown",
                                 f"key share grows from 32 B to {k['key_share_bytes']} B and certificate chains reach about 7.5 KB; "
                                 "free heap cannot be read from a firmware image",
                                 "measure free heap on the device during a TLS handshake"))
        elif a["id"] == "weak-today":
            repl = []
            if "MD5" in hit or "SHA1" in hit:
                repl.append(("SHA-256", "SHA256" in present))
            if "DES" in hit:
                repl.append(("AES", "AES" in present))
            for name, have in repl:
                checks.append(_check(f"{name} already linked", "ok" if have else "unknown",
                                     f"{name} is already in the image, so switching adds little code" if have
                                     else f"{name} is not in the image; switching adds its code (size not measured)"))
        elif a["id"] == "aes-256":
            checks.append(_check("Key length", "unknown",
                                 "AES-128 and AES-256 use the same code and tables, so the key length cannot be read from the image",
                                 "check key sizes in the source or configuration"))
        verdict = max((c["status"] for c in checks), key=lambda s: RANK[s]) if checks else "unknown"
        out.append({"id": a["id"], "title": a["title"], "families": a["families"], "triggeredBy": hit,
                    "verdict": verdict, "checks": checks})
    return out


def chip_scope(fw):
    """Which parts of the scanner are valid for this chip (P3.2)."""
    chip = fw.chip.split(" ")[0]
    kind = isa(chip)
    scope = {"chip": fw.chip, "isa": kind,
             "dataRules": "applies: constants, OIDs, keys and names do not depend on the instruction set",
             "hwRegisters": "applies: ESP32 crypto accelerator addresses (ESP32 TRM)" if chip == "ESP32"
             else "skipped: accelerator addresses are only mapped for ESP32",
             "mlTier": "applies: trained on ESP32 windowed-ABI code" if chip == "ESP32"
             else ("not validated: Xtensa LX7, model trained on ESP32 only" if kind == "xtensa"
                   else "not available: RISC-V code needs its own disassembler")}
    return scope


def for_result(result):
    """Feasibility actions and chip scope for a ScanResult (families present at the scan threshold)."""
    from .detect import present_families
    from .taxonomy import FAMILIES
    present = present_families(result, families=list(FAMILIES))
    signed = any(k.source == "secure-boot-v2" for k in result.keys)
    return assess(result.firmware, present, signed), chip_scope(result.firmware)


def summary_lines(actions):
    lines = []
    for a in actions:
        if not a["triggeredBy"]:
            continue
        lines.append(f"{a['title']}: {a['verdict']}")
        for c in a["checks"]:
            lines.append(f"  - {c['check']}: {c['status']}. {c['detail']}")
    return lines

"""Post-quantum rules (P2.9): constants derived from FIPS 203/204, verified against real firmware bytes."""

import json
import struct
from pathlib import Path

import pytest

from cbomscan import signatures as S
from cbomscan.cbom import build_cbom
from cbomscan.detect import present_families, scan
from cbomscan.image import load
from cbomscan.taxonomy import FAMILIES, PQC_FAMILIES, SCORED_FAMILIES
from cbomscan.validate import validate

ROOT = Path(__file__).resolve().parent.parent
PQC = ROOT / "dataset" / "out_pqc" / "samples"
PHASE1 = ROOT / "dataset" / "out" / "samples"


def _all_samples():
    return sorted(PQC.iterdir()) if PQC.exists() else []


def _samples():
    """ML-KEM / ML-DSA images (zeta-table rules); LMS images have their own tests below."""
    return [d for d in _all_samples() if not d.name.startswith("hashsigs")]


def test_zeta_derivation_matches_published_values():
    # First entries of FIPS 203 Appendix A and FIPS 204 Appendix B (zeta^BitRev(i) mod q).
    assert S.MLKEM_ZETAS[:6] == [1, 1729, 2580, 3289, 2642, 630]
    assert S.MLDSA_ZETAS[:6] == [1, 4808194, 3765607, 3761513, 5178923, 5496691]
    assert pow(S.MLKEM_ZETA, 128, S.MLKEM_Q) == S.MLKEM_Q - 1      # 17 is a primitive 256th root of unity
    assert pow(S.MLDSA_ZETA, 256, S.MLDSA_Q) == S.MLDSA_Q - 1      # 1753 is a primitive 512th root of unity
    assert S.MLKEM_ZETAS_MONT[:3] == [-1044, -758, -359]            # Montgomery form, as in the reference code
    assert S.MLDSA_ZETAS_MONT[1:3] == [25847, -2608894]


def test_pqc_families_are_not_vulnerable_and_not_scored():
    for f in PQC_FAMILIES:
        assert not FAMILIES[f].quantum_vulnerable
        assert f not in SCORED_FAMILIES            # keeps the Phase I metrics reproducible
    assert FAMILIES["MLKEM"].nist_quantum_level > 0 and FAMILIES["MLDSA"].nist_quantum_level > 0


@pytest.mark.skipif(not _samples(), reason="dataset/out_pqc not built")
@pytest.mark.parametrize("d", _samples(), ids=lambda d: d.name)
def test_derived_table_equals_bytes_of_real_build(d):
    t = json.loads((d / "truth.json").read_text())
    fam = t["present_families"][0]
    fw = load(d / "firmware.bin")
    assert t["reference_tables"], "no zeta table symbol recorded in the unstripped ELF"
    ref = t["reference_tables"][0]
    seg = fw.segment_at(ref["address"])
    raw = seg.data[ref["address"] - seg.addr:][:ref["size"]]
    if fam == "MLKEM":
        assert list(struct.unpack("<128h", raw)) == S.MLKEM_ZETAS_MONT
    else:
        vals = list(struct.unpack("<256i", raw))
        assert vals[1:] == S.MLDSA_ZETAS_MONT[1:]   # entry 0 is an unused 0 in the reference code


@pytest.mark.skipif(not _samples(), reason="dataset/out_pqc not built")
@pytest.mark.parametrize("d", _samples(), ids=lambda d: d.name)
def test_scan_finds_exactly_the_linked_pqc_family(d):
    t = json.loads((d / "truth.json").read_text())
    res = scan(load(d / "firmware.bin"))
    assert present_families(res, families=PQC_FAMILIES) == set(t["present_families"])
    fam = t["present_families"][0]
    bom = build_cbom(res)
    assert validate(bom) == []
    comp = next(c for c in bom["components"] if c["name"] == FAMILIES[fam].name)
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["cbomscan:quantumVulnerable"] == "false" and props["cbomscan:postQuantum"] == "true"
    assert comp["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] > 0


@pytest.mark.skipif(not PHASE1.exists(), reason="Phase I dataset not built")
def test_no_pqc_evidence_on_any_phase1_image():
    for d in sorted(PHASE1.iterdir()):
        res = scan(load(d / "firmware.bin"))
        assert [e.rule for e in res.evidence if e.family in PQC_FAMILIES] == [], d.name


# ---- LMS / HSS (RFC 8554) -----------------------------------------------------------------------

import functools


@functools.lru_cache(maxsize=None)
def _expected_lms_key(name):
    gen = _gen_lms_module()
    lt, ot = next((lt, ot) for n, lt, ot in gen.SETS if n == name)
    I = gen.H(b"cbomscan-lms-I-" + name.encode())[:16]
    seed = gen.H(b"cbomscan-lms-seed-" + name.encode())
    return lt, ot, gen.u32(1) + gen.lms_public_key(lt, ot, I, seed)


@functools.lru_cache(maxsize=None)
def _gen_lms_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_lms_keys", ROOT / "dataset" / "gen_lms_keys.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _lms_samples(embedded=True):
    return [d for d in _all_samples() if d.name.startswith("hashsigs") and ("nokey" not in d.name) == embedded]


def test_lms_type_codes_match_hash_sigs_source():
    hdr = ROOT / "third_party" / "hash-sigs" / "common_defs.h"
    if not hdr.exists():
        pytest.skip("third_party/hash-sigs not fetched")
    import re
    defs = {m.group(1): int(m.group(2), 16)
            for m in re.finditer(r"#define\s+((?:LMS|LMOTS)_SHA256_N32_\w+)\s+(0x[0-9a-fA-F]+)", hdr.read_text())}
    assert {v for k, v in defs.items() if k.startswith("LMS_")} == set(S.LMS_TYPES)
    assert {v for k, v in defs.items() if k.startswith("LMOTS_")} == set(S.LMOTS_TYPES)
    for k, v in defs.items():     # names: hash-sigs "LMS_SHA256_N32_H10" == RFC 8554 "LMS_SHA256_M32_H10"
        table = S.LMS_TYPES if k.startswith("LMS_") else S.LMOTS_TYPES
        assert table[v].split("_")[-1] == k.split("_")[-1]


@pytest.mark.skipif(not _lms_samples(), reason="LMS images not built")
@pytest.mark.parametrize("d", _lms_samples(), ids=lambda d: d.name)
def test_lms_embedded_key_found_and_structure_matches_rfc8554(d):
    t = json.loads((d / "truth.json").read_text())
    fw = load(d / "firmware.bin")
    ref = t["reference_tables"][0]
    seg = fw.segment_at(ref["address"])
    raw = seg.data[ref["address"] - seg.addr:][:ref["size"]]
    name = d.name.split("__")[0].replace("hashsigs_", "")
    lt, ot, expected = _expected_lms_key(name)
    assert raw == expected   # image bytes == the RFC 8554 key our generator produced
    res = scan(fw)
    assert "LMS" in present_families(res, families=PQC_FAMILIES)
    ev = res.findings["LMS"].evidence[0]
    assert S.LMS_TYPES[lt] in ev.detail and S.LMOTS_TYPES[ot] in ev.detail and ev.address == ref["address"]
    bom = build_cbom(res)
    assert validate(bom) == []
    comp = next(c for c in bom["components"] if c["name"] == FAMILIES["LMS"].name)
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["cbomscan:quantumVulnerable"] == "false" and props["cbomscan:postQuantum"] == "true"


@pytest.mark.skipif(not _lms_samples(embedded=False), reason="LMS images not built")
@pytest.mark.parametrize("d", _lms_samples(embedded=False), ids=lambda d: d.name)
def test_lms_verifier_without_embedded_key_is_a_known_miss(d):
    """Pins the documented blind spot: verifier code is linked but no key structure is in the image."""
    t = json.loads((d / "truth.json").read_text())
    assert t["present_families"] == ["LMS"]
    assert "LMS" not in present_families(scan(load(d / "firmware.bin")), families=PQC_FAMILIES)


def test_lms_structure_rule_rejects_low_entropy_and_unknown_codes():
    from types import SimpleNamespace
    from cbomscan.detect import _scan_lms
    sig = next(s for s in S.SIGNATURES if s.id == "lms.pubkey")
    good = bytes.fromhex("00000006" "00000003") + bytes(range(7, 55))
    mk = lambda data: SimpleNamespace(segments=[SimpleNamespace(data=data, addr=0x3F400000, region="DROM")])
    assert _scan_lms(mk(b"\xAA" * 8 + good + b"\xAA" * 8), sig)
    assert not _scan_lms(mk(bytes.fromhex("00000006" "00000003") + b"\x00" * 48), sig)           # zeros
    assert not _scan_lms(mk(bytes.fromhex("0000000A" "00000003") + bytes(range(7, 55))), sig)    # type 10 unassigned
    assert not _scan_lms(mk(bytes.fromhex("00000006" "00000005") + bytes(range(7, 55))), sig)    # OTS type 5 unassigned

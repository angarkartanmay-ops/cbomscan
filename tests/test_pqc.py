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


def _samples():
    return sorted(PQC.iterdir()) if PQC.exists() else []


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

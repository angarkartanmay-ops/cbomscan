import json
from pathlib import Path

import pytest

from cbomscan.cbom import build_cbom
from cbomscan.detect import present_families, scan
from cbomscan.image import load
from cbomscan.validate import validate

DS = Path(__file__).resolve().parent.parent / "dataset" / "out" / "samples"
pytestmark = pytest.mark.skipif(not DS.exists(), reason="dataset not built")


def _sample(name):
    d = DS / name
    return load(d / "firmware.bin"), json.loads((d / "truth.json").read_text())


def test_noncrypto_has_no_findings():
    fw, truth = _sample("m36__Os__noncrypto")
    assert truth["present_families"] == []
    assert present_families(scan(fw)) == set()


def test_rom_tables_full_stack_has_no_false_positives():
    fw, truth = _sample("m36rom__Os__full_stack")
    found = present_families(scan(fw))
    assert found <= set(truth["present_families"])
    assert {"AES", "DES", "MD5", "SHA1", "SHA256", "SHA512", "RSA", "ECC", "FFDH", "CHACHA20"} <= found


def test_secure_boot_blocks():
    for name, alg, bits in [("m36__Os__ota_rsa_pss__sbv2_rsa3072", "RSA", 3072),
                            ("m36__Os__ota_rsa_pss__sbv2_ecdsa_p256", "ECDSA", 256)]:
        fw, _ = _sample(name)
        assert len(fw.signature_blocks) == 1
        b = fw.signature_blocks[0]
        assert b.crc_ok and b.key_bits == bits
        assert (b.scheme == "RSA-PSS") == (alg == "RSA")


def test_stripped_elf_matches_bin():
    d = DS / "m228__O2__ota_ecdsa_p256"
    if not (d / "firmware.stripped.elf").exists():
        pytest.skip("stripped ELF not shipped; rebuild the dataset to run this test")
    a = present_families(scan(load(d / "firmware.bin")))
    b = present_families(scan(load(d / "firmware.stripped.elf")))
    assert a == b


def test_cbom_schema_valid():
    fw, _ = _sample("m36rom__Os__full_stack")
    assert validate(build_cbom(scan(fw))) == []

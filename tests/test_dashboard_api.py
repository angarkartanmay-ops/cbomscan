from pathlib import Path

from cbomscan.api import scan_to_dict

SAMPLE = Path(__file__).resolve().parent.parent / "dataset" / "out" / "samples" / "m36rom__Os__full_stack__sbv2_rsa3072" / "firmware.bin"


def test_scan_to_dict_shape():
    d = scan_to_dict(SAMPLE, "x")
    assert d["chip"] == "ESP32"
    assert len(d["families"]) == 13
    assert d["secureBoot"][0]["crcOk"]
    rsa = next(f for f in d["families"] if f["id"] == "RSA")
    assert rsa["quantumVulnerable"] and rsa["confidence"] >= 0.5 and rsa["evidence"]

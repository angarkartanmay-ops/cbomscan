import struct

import pytest

from cbomscan.image import parse_app_image, parse_signature_block


def _image(segs):
    hdr = bytes([0xE9, len(segs), 2, 0x20]) + struct.pack("<I", 0x40080000)
    ext = bytes([0xEE, 0, 0, 0]) + struct.pack("<HBHH", 0, 0, 0, 0xFFFF) + b"\0" * 4 + b"\0"
    body = b""
    for addr, data in segs:
        body += struct.pack("<II", addr, len(data)) + data
    raw = hdr + ext + body
    pad = 16 - len(raw) % 16
    return raw + b"\0" * pad


def test_parse_minimal_image():
    raw = _image([(0x3F400020, b"\x32\x54\xcd\xab" + b"\0" * 252), (0x400D0020, b"\x11" * 64)])
    fw = parse_app_image(raw)
    assert fw.chip == "ESP32"
    assert [s.region for s in fw.segments] == ["DROM", "IROM"]
    assert fw.segments[1].kind == "code"


def test_rejects_non_image():
    with pytest.raises(ValueError):
        parse_app_image(b"\x00" * 64)


def test_unknown_signature_version_ignored():
    blk = bytes([0xE7, 0x09]) + b"\0" * 1214
    assert parse_signature_block(blk, 0, 0) is None

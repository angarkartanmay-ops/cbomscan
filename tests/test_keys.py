import subprocess

import pytest

from cbomscan.keys import find_spki


def _der(args, tmp_path):
    key = tmp_path / "k.pem"
    subprocess.run(["openssl", "genpkey", *args, "-out", str(key)], check=True, capture_output=True)
    out = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"], check=True,
                         capture_output=True)
    return out.stdout


@pytest.mark.parametrize("args,alg,bits,param", [
    (["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"], "RSA", 2048, None),
    (["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], "EC", 256, "P-256"),
    (["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"], "EC", 384, "P-384"),
    (["-algorithm", "X25519"], "X25519", 255, "Curve25519"),
])
def test_spki_found_inside_noise(tmp_path, args, alg, bits, param):
    der = _der(args, tmp_path)
    blob = b"\x00" * 37 + der + b"\xff" * 19
    found = find_spki(blob)
    assert len(found) == 1
    off, a, b, p, size, fp = found[0]
    assert (off, a, b, p, size) == (37, alg, bits, param, len(der))


def test_bare_oid_is_not_a_key():
    assert find_spki(bytes.fromhex("06092A864886F70D010101") * 3) == []

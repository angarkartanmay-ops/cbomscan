"""Strings-only baseline: keyword matching over printable strings, as string-based firmware CBOM tools do."""

import re

KEYWORDS = {
    "AES": r"\baes",
    "DES": r"\b3?des\b|des-ede|triple-?des|\bdes3",
    "CHACHA20": r"chacha",
    "POLY1305": r"poly1305",
    "MD5": r"\bmd5",
    "SHA1": r"\bsha-?1\b|\bsha1",
    "SHA256": r"sha-?256|sha-?224",
    "SHA512": r"sha-?512|sha-?384",
    "RSA": r"\brsa",
    "ECDSA": r"ecdsa",
    "ECDH": r"ecdh|x25519|curve25519",
    "ECC": r"secp\d|prime256|\becc\b|ecdsa|ecdh|curve25519|\bec\b",
    "FFDH": r"\bdhm\b|diffie|ffdhe|\bmodp\b|\bdh\b",
}
_RX = {k: re.compile(v, re.I) for k, v in KEYWORDS.items()}
_PRINT = re.compile(rb"[\x20-\x7e]{4,}")


def strings_of(raw):
    return [m.group().decode("ascii") for m in _PRINT.finditer(raw)]


def detect(raw):
    found = set()
    hits = {}
    for s in strings_of(raw):
        for fam, rx in _RX.items():
            if rx.search(s):
                found.add(fam)
                hits.setdefault(fam, s)
    return found, hits

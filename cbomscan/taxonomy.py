"""Algorithm families scored by cbomscan, with quantum-risk classification and migration guidance."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Family:
    id: str
    name: str
    primitive: str
    quantum_vulnerable: bool
    nist_quantum_level: Optional[int]
    classical_status: str
    risk: str
    replacement: str
    note: str = ""
    pk_class: Optional[str] = None


FAMILIES = {
    "AES": Family("AES", "AES", "block-cipher", False, 1, "approved",
                  "low", "Keep AES; prefer AES-256 for data that must stay secret past ~2035 (Grover margin).",
                  "Level shown is the AES-128 lower bound; key size is not recovered from the binary in Phase I."),
    "DES": Family("DES", "DES / 3DES", "block-cipher", False, 0, "deprecated (classically weak)",
                  "high", "Replace with AES-256 (classical weakness, independent of quantum)."),
    "CHACHA20": Family("CHACHA20", "ChaCha20", "stream-cipher", False, 5, "approved",
                       "low", "Keep (256-bit key)."),
    "POLY1305": Family("POLY1305", "Poly1305", "mac", False, None, "approved",
                       "low", "Keep (one-time MAC, not affected by Shor)."),
    "MD5": Family("MD5", "MD5", "hash", False, 0, "broken (collisions)",
                  "high", "Replace with SHA-256 or SHA-3 (classically broken)."),
    "SHA1": Family("SHA1", "SHA-1", "hash", False, 0, "deprecated (collisions)",
                   "high", "Replace with SHA-256 or SHA-3 (classically broken for signatures)."),
    "SHA256": Family("SHA256", "SHA-256", "hash", False, 2, "approved",
                     "low", "Keep; SHA-384 if CNSA 2.0 compliance is required."),
    "SHA512": Family("SHA512", "SHA-384/512", "hash", False, 4, "approved",
                     "low", "Keep.", "Level 4 is the SHA-384 lower bound; the same code serves SHA-512."),
    "RSA": Family("RSA", "RSA", "signature", True, 0, "approved until 2030 (NIST IR 8547 draft)",
                  "critical", "Signatures: ML-DSA-65 (FIPS 204), or LMS/XMSS (SP 800-208) for firmware signing, hybrid with RSA during transition. Key transport: ML-KEM-768 (FIPS 203).",
                  "Broken by Shor's algorithm (integer factoring).", "RSA"),
    "ECDSA": Family("ECDSA", "ECDSA", "signature", True, 0, "approved until 2030 (NIST IR 8547 draft)",
                    "critical", "ML-DSA-44/65 (FIPS 204), hybrid ECDSA+ML-DSA during transition; LMS/XMSS for firmware signing.",
                    "Broken by Shor's algorithm (elliptic-curve discrete log).", "ECC"),
    "ECDH": Family("ECDH", "ECDH / X25519", "key-agree", True, 0, "approved until 2030 (NIST IR 8547 draft)",
                   "critical", "Hybrid X25519MLKEM768 (ML-KEM-768, FIPS 203). Highest priority: exposed to harvest-now-decrypt-later today.",
                   "Broken by Shor's algorithm (elliptic-curve discrete log).", "ECC"),
    "ECC": Family("ECC", "Elliptic-curve arithmetic", "other", True, 0, "approved until 2030 (NIST IR 8547 draft)",
                  "critical", "Identify the operation (ECDSA or ECDH) and migrate per that row.",
                  "Curve arithmetic present; the operation using it is not separated by Phase I rules.", "ECC"),
    "FFDH": Family("FFDH", "Finite-field Diffie-Hellman", "key-agree", True, 0, "approved until 2030 (NIST IR 8547 draft)",
                   "critical", "ML-KEM-768 (FIPS 203), hybrid during transition.",
                   "Broken by Shor's algorithm (discrete log).", "FFDH"),
}

SCORED_FAMILIES = ["AES", "DES", "CHACHA20", "POLY1305", "MD5", "SHA1", "SHA256", "SHA512",
                   "RSA", "ECDSA", "ECDH", "ECC", "FFDH"]

PK_CLASSES = ["RSA", "ECC", "FFDH"]

OBJECT_FAMILY = {
    "aes": "AES", "des": "DES", "chacha20": "CHACHA20", "poly1305": "POLY1305",
    "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "sha512": "SHA512",
    "rsa": "RSA", "rsa_internal": "RSA", "rsa_alt_helpers": "RSA",
    "ecdsa": "ECDSA", "ecdh": "ECDH", "ecp": "ECC", "ecp_curves": "ECC",
    "dhm": "FFDH",
}

OBJECT_SUPPORT = {
    "gcm": "GCM", "ctr_drbg": "CTR_DRBG", "hkdf": "HKDF", "chachapoly": "AEAD",
    "bignum": "BIGNUM", "bignum_core": "BIGNUM",
    "md": "SUPPORT", "cipher": "SUPPORT", "cipher_wrap": "SUPPORT", "pk": "SUPPORT", "pk_wrap": "SUPPORT",
    "pkparse": "SUPPORT", "pk_ecc": "SUPPORT", "oid": "SUPPORT", "asn1parse": "SUPPORT",
    "asn1write": "SUPPORT", "base64": "SUPPORT", "pem": "SUPPORT", "platform_util": "SUPPORT",
    "constant_time": "SUPPORT",
}

SECTION_FAMILY_OVERRIDES = [
    ("esp_sha_hw", "SHA256"),
    ("esp_aes_hw", "AES"),
]


def pk_class_of(family_id):
    fam = FAMILIES.get(family_id)
    return fam.pk_class if fam else None

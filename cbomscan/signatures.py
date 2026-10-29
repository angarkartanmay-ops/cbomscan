"""Constant signatures for cryptographic algorithms.

Values come from the algorithm specifications (FIPS 197, 180-4, RFC 1321, RFC 7539,
SEC 2 / FIPS 186, RFC 3526/7919, RFC 7748) and are generated here where possible,
so the rules are not tied to one library's source code. DES SP-boxes follow the
widely reused d3des layout (mbedTLS, PolarSSL and others).
"""

import math
import struct
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Signature:
    id: str
    family: str
    kind: str
    patterns: List[bytes] = field(default_factory=list)
    words: List[int] = field(default_factory=list)
    min_hits: int = 1
    confidence: float = 0.9
    description: str = ""
    group: str = "constants"
    param: Optional[str] = None
    guard: Optional[str] = None


def _xtime(x):
    x <<= 1
    return (x ^ 0x11B) if x & 0x100 else x


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def aes_sbox():
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if _gmul(i, j) == 1:
                inv[i] = j
                break
    sbox = []
    for i in range(256):
        b = inv[i]
        s = b
        for k in range(1, 5):
            s ^= ((b << k) | (b >> (8 - k))) & 0xFF
        sbox.append(s ^ 0x63)
    return bytes(sbox)


AES_SBOX = aes_sbox()
AES_INV_SBOX = bytes(AES_SBOX.index(i) for i in range(256))


def _table_words(box, mults, n=16):
    out = []
    for i in range(n):
        x = box[i]
        out.append(bytes(_gmul(x, m) for m in mults))
    return out


def _word_table_patterns(box, mults, n=16):
    be = _table_words(box, mults, n)
    p1 = b"".join(be)
    p2 = b"".join(w[::-1] for w in be)
    return [p1, p2]


def _words_le(ws):
    return b"".join(struct.pack("<I", w) for w in ws)


def _words_be(ws):
    return b"".join(struct.pack(">I", w) for w in ws)


def _u64_le(ws):
    return b"".join(struct.pack("<Q", w) for w in ws)


def _num_patterns(hexstr):
    be = bytes.fromhex(hexstr)
    return [be, be[::-1]]


MD5_T = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]

SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
]
SHA256_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
SHA224_IV = [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4]
SHA512_K = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
]
SHA512_IV = [0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
             0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179]
SHA384_IV = [0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
             0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4]
SHA1_K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
SHA1_IV5 = 0xC3D2E1F0
CHACHA_SIGMA = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]

DES_SP_HEADS = [
    [0x01010400, 0x00000000, 0x00010000, 0x01010404],
    [0x80108020, 0x80008000, 0x00008000, 0x00108020],
    [0x00000208, 0x08020200, 0x00000000, 0x08020008],
    [0x00802001, 0x00002081, 0x00002081, 0x00000080],
    [0x00000100, 0x02080100, 0x02080000, 0x42000100],
    [0x20000010, 0x20400000, 0x00004000, 0x20404010],
    [0x00200000, 0x04200002, 0x04000802, 0x00000000],
    [0x10001040, 0x00001000, 0x00040000, 0x10041040],
]
DES_FIPS_S1 = bytes([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7])
DES_FIPS_S1_ROW1 = bytes([0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8])

P256 = {
    "b": "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
    "gx": "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
    "gy": "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    "n": "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
}
P384 = {
    "b": "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
    "gx": "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
}
P521_B = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"
SECP256K1_GX = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
X25519_N_LOW = "14DEF9DEA2F79CD65812631A5CF5D3ED"
X25519_P = "7F" + "FF" * 30 + "ED"
MODP_PREFIX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
FFDHE_PREFIX = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"


def _der_oid(dotted_body_hex):
    b = bytes.fromhex(dotted_body_hex)
    return [bytes([0x06, len(b)]) + b]


SIGNATURES: List[Signature] = []


def _add(*a, **k):
    SIGNATURES.append(Signature(*a, **k))


_add("aes.sbox", "AES", "bytes", [AES_SBOX[:64]], confidence=0.95, description="AES forward S-box")
_add("aes.inv_sbox", "AES", "bytes", [AES_INV_SBOX[:64]], confidence=0.95, description="AES inverse S-box")
_add("aes.te_table", "AES", "bytes",
     _word_table_patterns(AES_SBOX, (0x02, 0x01, 0x01, 0x03)) + _word_table_patterns(AES_SBOX, (0x03, 0x01, 0x01, 0x02)),
     confidence=0.95, description="AES encryption T-table (Te/FT)")
_add("aes.td_table", "AES", "bytes",
     _word_table_patterns(AES_INV_SBOX, (0x0E, 0x09, 0x0D, 0x0B)) + _word_table_patterns(AES_INV_SBOX, (0x0B, 0x0D, 0x09, 0x0E)),
     confidence=0.95, description="AES decryption T-table (Td/RT)")
_add("aes.rcon", "AES", "bytes",
     [_words_le([1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]), bytes([1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])],
     confidence=0.7, description="AES key-schedule round constants")

_add("des.sp_boxes", "DES", "bytes", [_words_le(h) for h in DES_SP_HEADS], min_hits=3, confidence=0.95,
     description="DES combined S/P tables (d3des layout)")
_add("des.fips_sbox", "DES", "bytes", [DES_FIPS_S1 + DES_FIPS_S1_ROW1], confidence=0.9,
     description="DES S-box S1 (FIPS 46-3 byte table)")

_add("md5.t", "MD5", "words", words=MD5_T, min_hits=16, confidence=0.95,
     description="MD5 sine-derived round constants (as literal-pool or table words)")
_add("md5.t_table", "MD5", "bytes", [_words_le(MD5_T[:16])], confidence=0.97, description="MD5 constant table")

_add("sha1.k", "SHA1", "words", words=SHA1_K + [SHA1_IV5], min_hits=4, confidence=0.85,
     description="SHA-1 round constants and fifth IV word")

_add("sha256.k", "SHA256", "bytes", [_words_le(SHA256_K), _words_be(SHA256_K)], confidence=0.97,
     description="SHA-256 round-constant table K[0..31]")
_add("sha256.iv", "SHA256", "words", words=SHA256_IV + SHA224_IV, min_hits=6, confidence=0.75,
     description="SHA-256/224 initial hash values")

_add("sha512.k", "SHA512", "bytes", [_u64_le(SHA512_K), b"".join(struct.pack(">Q", w) for w in SHA512_K)],
     confidence=0.97, description="SHA-512 round-constant table K[0..11]")
_add("sha512.iv", "SHA512", "words",
     words=[w & 0xFFFFFFFF for w in SHA512_IV] + [w >> 32 for w in SHA384_IV], min_hits=8,
     confidence=0.8, description="SHA-512/384 initial hash values (32-bit halves not shared with SHA-256/224 IVs)")

_add("chacha20.sigma", "CHACHA20", "words", words=CHACHA_SIGMA, min_hits=3, confidence=0.9,
     description="ChaCha20 'expand 32-byte k' constants")
_add("chacha20.sigma_str", "CHACHA20", "bytes", [b"expand 32-byte k"], confidence=0.9,
     description="ChaCha20/Salsa20 sigma string")
_add("poly1305.clamp", "POLY1305", "words", words=[0x0FFFFFFF, 0x0FFFFFFC], min_hits=2, confidence=0.55,
     description="Poly1305 key-clamp masks", guard="clustered")

_add("ecc.p256", "ECC", "bytes", [p for v in P256.values() for p in _num_patterns(v)], min_hits=2,
     confidence=0.97, description="NIST P-256 (secp256r1) domain parameters", param="P-256")
_add("ecc.p384", "ECC", "bytes", [p for v in P384.values() for p in _num_patterns(v)], min_hits=1,
     confidence=0.97, description="NIST P-384 (secp384r1) domain parameters", param="P-384")
_add("ecc.p521", "ECC", "bytes", _num_patterns(P521_B), confidence=0.97,
     description="NIST P-521 curve coefficient b", param="P-521")
_add("ecc.secp256k1", "ECC", "bytes", _num_patterns(SECP256K1_GX), confidence=0.97,
     description="secp256k1 generator x", param="secp256k1")
_add("ecc.x25519_order", "ECC", "bytes", _num_patterns(X25519_N_LOW), confidence=0.9,
     description="Curve25519 group order (low part)", param="Curve25519")
_add("ecc.x25519_p", "ECC", "bytes", _num_patterns(X25519_P), confidence=0.75,
     description="Curve25519 field prime 2^255-19", param="Curve25519")
_add("ecc.x25519_a24", "ECC", "words", words=[0x01DB42, 0x01DB41], min_hits=1, confidence=0.5,
     description="Curve25519 Montgomery ladder constant a24", param="Curve25519")

_add("ffdh.modp", "FFDH", "bytes", _num_patterns(MODP_PREFIX)[:1] + [MODP_PREFIX.encode(), MODP_PREFIX.lower().encode()],
     confidence=0.9, description="RFC 2409/3526 MODP group prime (prefix)")
_add("ffdh.ffdhe", "FFDH", "bytes", _num_patterns(FFDHE_PREFIX)[:1] + [FFDHE_PREFIX.encode()], confidence=0.9,
     description="RFC 7919 ffdhe group prime (prefix)")

# ---- Post-quantum algorithms (P2.9) -------------------------------------------------------------
# ML-KEM (FIPS 203): q = 3329, zeta = 17, zeta_i = 17^BitRev7(i) mod q (Appendix A).
# ML-DSA (FIPS 204): q = 8380417, zeta = 1753, zeta_i = 1753^BitRev8(i) mod q (Appendix B).
# Reference implementations store these tables in signed Montgomery form (x * 2^16 mod q for ML-KEM,
# x * 2^32 mod q for ML-DSA, centred on 0), so that is the form the rules match. It is derived here and
# verified against the bytes of real builds by tests/test_pqc.py (see docs/PQC_RULES.md). The plain FIPS
# appendix form is deliberately NOT matched: no implementation we could build stores it, so a rule for
# it would be unverified.


def _bitrev(x, bits):
    return int(format(x, f"0{bits}b")[::-1], 2)


def _centre(v, m):
    return v if v <= m // 2 else v - m


MLKEM_Q, MLKEM_ZETA = 3329, 17
MLDSA_Q, MLDSA_ZETA = 8380417, 1753
MLKEM_ZETAS = [pow(MLKEM_ZETA, _bitrev(i, 7), MLKEM_Q) for i in range(128)]
MLDSA_ZETAS = [pow(MLDSA_ZETA, _bitrev(i, 8), MLDSA_Q) for i in range(256)]
MLKEM_ZETAS_MONT = [_centre(z * 2 ** 16 % MLKEM_Q, MLKEM_Q) for z in MLKEM_ZETAS]
MLDSA_ZETAS_MONT = [_centre(z * 2 ** 32 % MLDSA_Q, MLDSA_Q) for z in MLDSA_ZETAS]

PQC_TABLE_ENTRIES = 16  # 32 (ML-KEM) / 64 (ML-DSA) bytes of high-entropy values: chance match is negligible


def _i16le(vs):
    return b"".join(struct.pack("<h", v) for v in vs)


def _i32le(vs):
    return b"".join(struct.pack("<i", v) for v in vs)


_add("mlkem.zetas_mont", "MLKEM", "bytes", [_i16le(MLKEM_ZETAS_MONT[:PQC_TABLE_ENTRIES])], confidence=0.95,
     description="ML-KEM (FIPS 203) NTT zeta table, signed Montgomery form int16")
_add("mldsa.zetas_mont", "MLDSA", "bytes", [_i32le(MLDSA_ZETAS_MONT[1:1 + PQC_TABLE_ENTRIES])], confidence=0.95,
     description="ML-DSA (FIPS 204) NTT zeta table, signed Montgomery form int32 (entry 0 skipped)")

# LMS / HSS (RFC 8554, NIST SP 800-208): public key = u32 lms_type | u32 lmots_type | I[16] | T1[32],
# preceded by a u32 level count for HSS. Type codes are big-endian u32.
LMS_TYPES = {5: "LMS_SHA256_M32_H5", 6: "LMS_SHA256_M32_H10", 7: "LMS_SHA256_M32_H15",
             8: "LMS_SHA256_M32_H20", 9: "LMS_SHA256_M32_H25"}
LMOTS_TYPES = {1: "LMOTS_SHA256_N32_W1", 2: "LMOTS_SHA256_N32_W2", 3: "LMOTS_SHA256_N32_W4",
               4: "LMOTS_SHA256_N32_W8"}
LMS_PUBKEY_LEN = 56
LMS_MIN_DISTINCT = 36  # distinct byte values required in the 48 random bytes (I and T1); expected ~44
_add("lms.pubkey", "LMS", "lms_pubkey", confidence=0.85,
     description="embedded LMS/HSS public key structure (RFC 8554 type codes followed by 48 high-entropy bytes)")

OID_RSA = "2A864886F70D010101"
OID_RSA_PSS = "2A864886F70D01010A"
OID_EC_PUBKEY = "2A8648CE3D0201"
OID_ECDSA_SHA256 = "2A8648CE3D040302"
OID_ECDSA_SHA384 = "2A8648CE3D040303"
OID_P256 = "2A8648CE3D030107"
OID_P384 = "2B81040022"
OID_X25519 = "2B656E"
OID_DH = "2A864886F70D010301"

_add("oid.rsa", "RSA", "bytes", [bytes.fromhex(OID_RSA)], confidence=0.45, group="oid",
     description="rsaEncryption OID (1.2.840.113549.1.1.1)")
_add("oid.rsa_pss", "RSA", "bytes", [bytes.fromhex(OID_RSA_PSS)], confidence=0.45, group="oid",
     description="RSASSA-PSS OID (1.2.840.113549.1.1.10)")
_add("oid.ecdsa", "ECDSA", "bytes", [bytes.fromhex(OID_ECDSA_SHA256), bytes.fromhex(OID_ECDSA_SHA384)],
     confidence=0.45, group="oid", description="ecdsa-with-SHA256/384 OID")
_add("oid.ec_pubkey", "ECC", "bytes", [bytes.fromhex(OID_EC_PUBKEY)], confidence=0.4, group="oid",
     description="id-ecPublicKey OID (1.2.840.10045.2.1)")
_add("oid.x25519", "ECDH", "bytes", _der_oid(OID_X25519), confidence=0.4, group="oid",
     description="X25519 OID (1.3.101.110)")
_add("oid.dh", "FFDH", "bytes", [bytes.fromhex(OID_DH)], confidence=0.4, group="oid",
     description="dhKeyAgreement OID (1.2.840.113549.1.3.1)")

STRING_HINTS = [
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA", 0.35),
    ("-----BEGIN RSA PUBLIC KEY-----", "RSA", 0.35),
    ("-----BEGIN EC PRIVATE KEY-----", "ECC", 0.35),
    ("-----BEGIN DH PARAMETERS-----", "FFDH", 0.35),
]

NAME_TOKENS = {
    "AES": r"\bAES(?:-(?:128|192|256))?(?:-[A-Z0-9]+)?\b",
    "DES": r"\bDES(?:-EDE3?)?(?:-[A-Z]+)?\b|\b3DES\b",
    "CHACHA20": r"\bCHACHA20(?:-POLY1305)?\b",
    "POLY1305": r"\bPOLY1305\b|\bCHACHA20-POLY1305\b",
    "MD5": r"\bMD5\b",
    "SHA1": r"\bSHA-?1\b",
    "SHA256": r"\bSHA-?(?:224|256)\b",
    "SHA512": r"\bSHA-?(?:384|512)\b",
    "RSA": r"\bRSA(?:-(?:PSS|OAEP|alt))?\b|\bRSASSA_PSS\b",
    "ECDSA": r"\bECDSA\b",
    "ECDH": r"\bEC_?DH\b|\bX25519\b",
    "FFDH": r"\bDHM\b|\bffdhe\d+\b",
}
NAME_CONFIDENCE = 0.4

LIBRARY_HINTS = [
    (b"mbedtls", "Mbed TLS"), (b"Mbed TLS", "Mbed TLS"), (b"mbed TLS", "Mbed TLS"),
    (b"wolfSSL", "wolfSSL"), (b"BearSSL", "BearSSL"), (b"OpenSSL", "OpenSSL"), (b"tinycrypt", "TinyCrypt"),
    (b"micro-ecc", "micro-ecc"), (b"esp-pqc", "esp-pqc"), (b"liboqs", "liboqs"),
]

HW_WINDOWS = [
    (0x3FF01000, 0x3FF01100, "AES", "ESP32 AES accelerator registers"),
    (0x3FF03000, 0x3FF03100, "SHA256", "ESP32 SHA accelerator registers"),
    (0x3FF02000, 0x3FF02900, "PK_HW", "ESP32 RSA/MPI accelerator registers (big-number arithmetic for RSA/ECC)"),
]

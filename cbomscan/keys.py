"""Find public-key material embedded in firmware: DER/PEM SubjectPublicKeyInfo and Secure Boot V2 blocks."""

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import List, Optional

OID_RSA = bytes.fromhex("06092A864886F70D010101")
OID_EC = bytes.fromhex("06072A8648CE3D0201")
OID_X25519 = bytes.fromhex("06032B656E")
OID_ED25519 = bytes.fromhex("06032B6570")
CURVE_OIDS = {
    bytes.fromhex("06082A8648CE3D030107"): ("P-256", 256),
    bytes.fromhex("06052B81040022"): ("P-384", 384),
    bytes.fromhex("06052B81040023"): ("P-521", 521),
    bytes.fromhex("06052B8104000A"): ("secp256k1", 256),
}
PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\r\n]+)-----END \1-----")


@dataclass
class KeyMaterial:
    algorithm: str
    bits: int
    param: Optional[str]
    source: str
    address: Optional[int]
    region: str
    fmt: str
    fingerprint: str
    context: str = ""

    def describe(self):
        p = f" {self.param}" if self.param else ""
        return f"{self.algorithm}{p} public key ({self.bits}-bit, {self.fmt}{', ' + self.context if self.context else ''})"


def _tlv(buf, i):
    if i + 2 > len(buf):
        return None
    tag = buf[i]
    l = buf[i + 1]
    j = i + 2
    if l & 0x80:
        n = l & 0x7F
        if n == 0 or n > 3 or j + n > len(buf):
            return None
        l = int.from_bytes(buf[j:j + n], "big")
        j += n
    if j + l > len(buf):
        return None
    return tag, j, l


def _parse_spki(buf, start):
    t = _tlv(buf, start)
    if not t or t[0] != 0x30:
        return None
    _, body, blen = t
    end = body + blen
    alg = _tlv(buf, body)
    if not alg or alg[0] != 0x30:
        return None
    _, abody, alen = alg
    aend = abody + alen
    bs = _tlv(buf, aend)
    if not bs or bs[0] != 0x03 or bs[1] + bs[2] != end:
        return None
    algbytes = buf[abody:aend]
    bits_body = buf[bs[1] + 1: bs[1] + bs[2]]
    fp = hashlib.sha256(buf[start:end]).hexdigest()[:16]
    if algbytes.startswith(OID_RSA):
        seq = _tlv(bits_body, 0)
        if not seq or seq[0] != 0x30:
            return None
        n = _tlv(bits_body, seq[1])
        if not n or n[0] != 0x02:
            return None
        modulus = int.from_bytes(bits_body[n[1]:n[1] + n[2]], "big")
        return ("RSA", modulus.bit_length(), None, end - start, fp)
    if algbytes.startswith(OID_EC):
        rest = algbytes[len(OID_EC):]
        for oid, (name, bits) in CURVE_OIDS.items():
            if rest.startswith(oid):
                return ("EC", bits, name, end - start, fp)
        return ("EC", 0, "unknown-curve", end - start, fp)
    if algbytes.startswith(OID_X25519):
        return ("X25519", 255, "Curve25519", end - start, fp)
    if algbytes.startswith(OID_ED25519):
        return ("Ed25519", 255, "Curve25519", end - start, fp)
    return None


def find_spki(buf):
    out = []
    seen = set()
    for oid in (OID_RSA, OID_EC, OID_X25519, OID_ED25519):
        for m in re.finditer(re.escape(oid), buf):
            alg_start = m.start() - 2
            for back in range(2, 6):
                s = alg_start - back
                if s < 0 or buf[s] != 0x30:
                    continue
                r = _parse_spki(buf, s)
                if r and s not in seen:
                    seen.add(s)
                    out.append((s,) + r)
                    break
    return out


def _context(buf, s):
    lo = max(0, s - 16)
    window = buf[lo:s]
    return "inside X.509 certificate" if b"\x30\x82" in window and b"\xa0\x03\x02\x01" in buf[max(0, s - 400):s] else ""


def find_key_material(fw) -> List[KeyMaterial]:
    keys = []
    for seg in fw.segments:
        for s, alg, bits, param, size, fp in find_spki(seg.data):
            name = "RSA" if alg == "RSA" else alg
            keys.append(KeyMaterial(name, bits, param, "embedded-der", seg.addr + s, seg.region, "DER SPKI", fp,
                                    _context(seg.data, s)))
        for m in PEM_RE.finditer(seg.data):
            label = m.group(1).decode()
            try:
                der = base64.b64decode(re.sub(rb"\s+", b"", m.group(2)))
            except Exception:
                continue
            for s, alg, bits, param, size, fp in find_spki(der):
                keys.append(KeyMaterial(alg, bits, param, "embedded-pem", seg.addr + m.start(), seg.region,
                                        f"PEM ({label})", fp, "inside X.509 certificate" if "CERT" in label else ""))
    for sb in fw.signature_blocks:
        alg = "RSA" if sb.scheme == "RSA-PSS" else "ECDSA"
        fp = hashlib.sha256(sb.public_key).hexdigest()[:16]
        keys.append(KeyMaterial(alg, sb.key_bits, sb.curve or "PSS", "secure-boot-v2", None, "image-trailer",
                                "Secure Boot V2 signature block", fp,
                                f"block {sb.index}, CRC {'ok' if sb.crc_ok else 'BAD'}"))
    return keys

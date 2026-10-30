"""Tier-1 rule-based detection of cryptographic algorithms in ESP32 firmware."""

import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from . import signatures as S
from .image import Firmware
from .keys import find_key_material
from .taxonomy import FAMILIES, SCORED_FAMILIES

DEFAULT_THRESHOLD = 0.5


@dataclass
class Evidence:
    family: str
    rule: str
    group: str
    method: str
    confidence: float
    address: Optional[int]
    region: str
    detail: str
    param: Optional[str] = None
    xrefs: List[int] = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["address"] = None if self.address is None else f"0x{self.address:08x}"
        d["xrefs"] = [f"0x{x:08x}" for x in self.xrefs]
        return d


@dataclass
class Finding:
    family: str
    confidence: float
    evidence: List[Evidence]
    params: List[str]
    execution: str
    present: bool

    @property
    def info(self):
        return FAMILIES[self.family]


@dataclass
class ScanResult:
    firmware: Firmware
    evidence: List[Evidence]
    findings: Dict[str, Finding]
    keys: list
    libraries: List[str]
    hw: List[Evidence]
    threshold: float
    groups: List[str]


class WordIndex:
    def __init__(self, fw: Firmware):
        self.addrs = defaultdict(list)
        for seg in fw.segments:
            d = seg.data
            base = seg.addr
            start = (-base) % 4
            n = (len(d) - start) // 4
            if n <= 0:
                continue
            words = struct.unpack_from(f"<{n}I", d, start)
            for i, w in enumerate(words):
                self.addrs[w].append(base + start + 4 * i)

    def find(self, w):
        return self.addrs.get(w, [])


def _code_xrefs(fw, words, lo, hi, limit=8):
    refs = []
    for seg in fw.segments:
        if seg.kind != "code":
            continue
        d = seg.data
        start = (-seg.addr) % 4
        n = (len(d) - start) // 4
        if n <= 0:
            continue
        for i, w in enumerate(struct.unpack_from(f"<{n}I", d, start)):
            if lo <= w < hi:
                refs.append(seg.addr + start + 4 * i)
                if len(refs) >= limit:
                    return refs
    return refs


def _scan_bytes(fw, sig, groups):
    out = []
    hits = []
    for pat in sig.patterns:
        found = None
        for seg in fw.segments:
            o = seg.data.find(pat)
            if o >= 0:
                found = (seg, o)
                break
        if found:
            hits.append((pat, found))
    distinct = len(hits)
    if distinct < sig.min_hits:
        return out
    seg, o = hits[0][1]
    addr = seg.addr + o
    plen = len(hits[0][0])
    xr = _code_xrefs(fw, None, addr, addr + max(plen, 256))
    conf = sig.confidence
    if xr:
        conf = min(0.99, conf + 0.02)
    detail = f"{sig.description}; {distinct}/{len(sig.patterns)} pattern(s) matched"
    if xr:
        detail += f"; referenced from code at {', '.join(hex(x) for x in xr[:3])}"
    out.append(Evidence(sig.family, sig.id, sig.group, "constant-match" if sig.group == "constants" else sig.group,
                        conf, addr, seg.region, detail, sig.param, xr))
    return out


_LMS_RX = re.compile(rb"\x00\x00\x00[\x05-\x09]\x00\x00\x00[\x01-\x04]", re.S)


def _scan_lms(fw, sig):
    """Find LMS/HSS public keys: known type codes, then 48 bytes (I, T1) that look random."""
    out = []
    for seg in fw.segments:
        for m in _LMS_RX.finditer(seg.data):
            o = m.start()
            body = seg.data[o + 8:o + S.LMS_PUBKEY_LEN]
            if len(body) < S.LMS_PUBKEY_LEN - 8 or len(set(body)) < S.LMS_MIN_DISTINCT:
                continue
            lms_t, ots_t = seg.data[o + 3], seg.data[o + 7]
            hss = o >= 4 and seg.data[o - 4:o] == b"\x00\x00\x00\x01"
            out.append(Evidence(sig.family, sig.id, sig.group, "structure-match", sig.confidence,
                                seg.addr + o - (4 if hss else 0), seg.region,
                                f"{sig.description}: {S.LMS_TYPES[lms_t]} + {S.LMOTS_TYPES[ots_t]}"
                                f"{' (HSS, 1 level)' if hss else ''}", f"{S.LMS_TYPES[lms_t]}/{S.LMOTS_TYPES[ots_t]}"))
            return out
    return out


def _scan_words(fw, idx, sig):
    found = {}
    for w in sig.words:
        a = idx.find(w)
        if a:
            found[w] = a
    if sig.guard == "clustered" and len(found) >= 2:
        addrs = sorted(a for v in found.values() for a in v)
        ok = any(addrs[i + 1] - addrs[i] <= 64 for i in range(len(addrs) - 1))
        if not ok:
            return []
    if len(found) < sig.min_hits:
        return []
    first = min(a for v in found.values() for a in v)
    seg = fw.segment_at(first)
    conf = sig.confidence
    if len(found) >= max(sig.min_hits * 2, len(sig.words) * 0.75):
        conf = min(0.99, conf + 0.04)
    return [Evidence(sig.family, sig.id, sig.group, "literal-pool-words", conf, first, seg.region if seg else "?",
                     f"{sig.description}; {len(found)}/{len(sig.words)} distinct constants found", sig.param)]


def _scan_strings(fw):
    ev = []
    libs = []
    for seg in fw.segments:
        if seg.kind != "data":
            continue
        for s, fam, conf in S.STRING_HINTS:
            o = seg.data.find(s.encode())
            if o >= 0:
                ev.append(Evidence(fam, "str." + re.sub(r"\W+", "_", s.strip("-")).lower(), "strings", "string-match",
                                   conf, seg.addr + o, seg.region, f"string '{s}'"))
        for pat, name in S.LIBRARY_HINTS:
            if pat in seg.data and name not in libs:
                libs.append(name)
    return ev, libs


_PRINTABLE = re.compile(rb"[\x20-\x7e]{2,}")
_NAME_RX = {f: re.compile(rx) for f, rx in S.NAME_TOKENS.items()}


def _scan_names(fw):
    ev = []
    seen = set()
    for seg in fw.segments:
        if seg.kind != "data":
            continue
        for m in _PRINTABLE.finditer(seg.data):
            txt = m.group().decode("ascii")
            if len(txt) > 40:
                continue
            for fam, rx in _NAME_RX.items():
                if fam in seen:
                    continue
                if rx.fullmatch(txt):
                    seen.add(fam)
                    ev.append(Evidence(fam, f"name.{fam.lower()}", "names", "algorithm-name-string",
                                       S.NAME_CONFIDENCE, seg.addr + m.start(), seg.region,
                                       f"algorithm name string '{txt}' (library metadata table)"))
    return ev


def _scan_hw(fw, idx):
    ev = []
    for lo, hi, fam, desc in S.HW_WINDOWS:
        refs = []
        for seg in fw.segments:
            if seg.kind != "code":
                continue
            d = seg.data
            start = (-seg.addr) % 4
            n = (len(d) - start) // 4
            if n <= 0:
                continue
            for i, w in enumerate(struct.unpack_from(f"<{n}I", d, start)):
                if lo <= w < hi:
                    refs.append((seg.addr + start + 4 * i, w, seg.region))
        if len(refs) >= 2:
            regs = sorted({w for _, w, _ in refs})
            a, _, region = refs[0]
            ev.append(Evidence(fam, f"hw.{fam.lower()}", "hw", "peripheral-register-reference", 0.85, a, region,
                               f"{desc}: {len(refs)} code references to {len(regs)} register(s) "
                               f"({', '.join(hex(r) for r in regs[:4])}{'...' if len(regs) > 4 else ''})"))
    return ev


def _combine(evs):
    best = {}
    for e in evs:
        if e.rule not in best or e.confidence > best[e.rule].confidence:
            best[e.rule] = e
    p = 1.0
    for e in best.values():
        p *= (1.0 - e.confidence)
    return min(0.99, 1.0 - p)


ALL_GROUPS = ["constants", "oid", "keys", "strings", "names", "hw", "secure-boot"]


def scan(fw: Firmware, threshold=DEFAULT_THRESHOLD, groups=None, ml=False) -> ScanResult:
    groups = list(groups or ALL_GROUPS)
    idx = WordIndex(fw)
    evidence: List[Evidence] = []
    for sig in S.SIGNATURES:
        if sig.group not in groups:
            continue
        if sig.kind == "bytes":
            evidence += _scan_bytes(fw, sig, groups)
        elif sig.kind == "lms_pubkey":
            evidence += _scan_lms(fw, sig)
        else:
            evidence += _scan_words(fw, idx, sig)
    sha512_seen = any(e.family == "SHA512" for e in evidence)
    if sha512_seen:
        for e in evidence:
            if e.rule == "sha256.iv":
                e.confidence = 0.25
                e.detail += "; discounted: every SHA-256/224 IV word is also half of a SHA-512/384 IV, and SHA-512 is present"
    libs = []
    if "strings" in groups:
        sev, libs = _scan_strings(fw)
        evidence += sev
    else:
        _, libs = _scan_strings(fw)
    if "names" in groups:
        evidence += _scan_names(fw)
    keys = find_key_material(fw)
    if "keys" in groups:
        for k in keys:
            if k.source == "secure-boot-v2":
                continue
            fam = "RSA" if k.algorithm == "RSA" else "ECC"
            evidence.append(Evidence(fam, f"key.{k.algorithm.lower()}", "keys", "embedded-key-material", 0.85,
                                     k.address, k.region, f"embedded {k.describe()}", k.param))
    if "secure-boot" in groups:
        for k in keys:
            if k.source != "secure-boot-v2":
                continue
            fam = "RSA" if k.algorithm == "RSA" else "ECDSA"
            evidence.append(Evidence(fam, f"sbv2.{k.algorithm.lower()}", "secure-boot", "secure-boot-signature-block",
                                     0.99, None, "image-trailer", f"Secure Boot V2 signature block: {k.describe()}",
                                     k.param))
    hw = _scan_hw(fw, idx) if "hw" in groups else []
    evidence += [e for e in hw if e.family in FAMILIES]

    if ml:   # Phase II, off by default: function-classifier evidence (cbomscan.ml)
        from .ml import ml_evidence
        evidence += ml_evidence(fw)

    by_fam = defaultdict(list)
    for e in evidence:
        by_fam[e.family].append(e)
    findings = {}
    for fam, evs in by_fam.items():
        conf = _combine(evs)
        params = sorted({e.param for e in evs if e.param})
        hw_only = all(e.group == "hw" for e in evs)
        execution = "hardware" if hw_only else ("software+hardware" if any(e.group == "hw" for e in evs) else "software")
        findings[fam] = Finding(fam, conf, sorted(evs, key=lambda e: -e.confidence), params, execution,
                                conf >= threshold)
    ecc_ops = [f for f in ("ECDSA", "ECDH") if f in findings and findings[f].present]
    if ecc_ops and "ECC" in findings:
        findings["ECC"].params = sorted(set(findings["ECC"].params) | {p for f in ecc_ops for p in findings[f].params})
    return ScanResult(fw, evidence, findings, keys, libs, hw, threshold, groups)


def present_families(result: ScanResult, include_implied=True, families=None):
    """Families reported present. Defaults to the 13 Phase I scored families; pass
    families=ALL_FAMILIES (taxonomy) to include the post-quantum ones."""
    allowed = SCORED_FAMILIES if families is None else families
    fams = {f for f, x in result.findings.items() if x.present and f in allowed}
    if include_implied and fams & {"ECDSA", "ECDH"}:
        fams.add("ECC")
    return fams

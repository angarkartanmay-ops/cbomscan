import time

from .detect import scan, DEFAULT_THRESHOLD
from .image import load
from .migration import PRIORITY, notes_for
from .taxonomy import FAMILIES, SCORED_FAMILIES, PQC_FAMILIES


def scan_to_dict(path, name=None, threshold=DEFAULT_THRESHOLD):
    start = time.perf_counter()
    fw = load(path)
    res = scan(fw, threshold=threshold)
    ms = round((time.perf_counter() - start) * 1000)
    families = []
    for fam in SCORED_FAMILIES + PQC_FAMILIES:
        info = FAMILIES[fam]
        f = res.findings.get(fam)
        priority, reason = PRIORITY.get(fam, (5, "No migration guidance recorded for this family yet."))
        families.append({
            "id": fam,
            "name": info.name,
            "primitive": info.primitive,
            "quantumVulnerable": info.quantum_vulnerable,
            "risk": info.risk,
            "nistLevel": info.nist_quantum_level,
            "classicalStatus": info.classical_status,
            "replacement": info.replacement,
            "note": info.note,
            "priority": priority,
            "priorityReason": reason,
            "confidence": round(f.confidence, 3) if f else 0,
            "execution": f.execution if f else None,
            "params": f.params if f else [],
            "costNotes": notes_for(fam, f.params if f else []),
            "evidence": [e.to_dict() for e in f.evidence] if f else [],
        })
    return {
        "name": name or fw.path,
        "sha256": fw.sha256,
        "container": fw.container,
        "chip": fw.chip,
        "entry": f"0x{fw.entry:08x}",
        "imageSize": fw.image_size,
        "app": {k: fw.app_desc.get(k) for k in ("project_name", "version", "idf_ver", "date")} if fw.app_desc else {},
        "segments": [{"index": s.index, "region": s.region, "kind": s.kind,
                      "addr": s.addr, "size": len(s.data)} for s in fw.segments],
        "secureBoot": [{"scheme": b.scheme, "keyBits": b.key_bits, "curve": b.curve, "crcOk": b.crc_ok}
                       for b in fw.signature_blocks],
        "keys": [k.describe() for k in res.keys],
        "libraries": res.libraries,
        "threshold": threshold,
        "scanMs": ms,
        "families": families,
    }

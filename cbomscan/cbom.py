"""Export scan results as a CycloneDX 1.6 Cryptography Bill of Materials (CBOM)."""

import datetime
import uuid

from . import __version__
from .migration import PRIORITY, PLATFORM_NOTES, notes_for, ESP_PQC_SOURCE
from .taxonomy import FAMILIES, PQC_FAMILIES

SPEC_VERSION = "1.6"

CRYPTO_FUNCTIONS = {
    "AES": ["encrypt", "decrypt"], "DES": ["encrypt", "decrypt"], "CHACHA20": ["encrypt", "decrypt"],
    "POLY1305": ["tag"], "MD5": ["digest"], "SHA1": ["digest"], "SHA256": ["digest"], "SHA512": ["digest"],
    "RSA": ["sign", "verify", "encrypt", "decrypt"], "ECDSA": ["sign", "verify"], "ECDH": ["keyderive"],
    "ECC": ["other"], "FFDH": ["keyderive"],
    "MLKEM": ["keygen", "encapsulate", "decapsulate"], "MLDSA": ["keygen", "sign", "verify"], "LMS": ["verify"],
}


def _prop(name, value):
    return {"name": f"cbomscan:{name}", "value": str(value)}


def _algorithm_component(f, ref):
    info = f.info
    alg = {"primitive": info.primitive,
           "executionEnvironment": "hardware" if f.execution == "hardware" else "software-plain-ram",
           "implementationPlatform": "other",
           "cryptoFunctions": CRYPTO_FUNCTIONS.get(f.family, ["unknown"])}
    if info.nist_quantum_level is not None:
        alg["nistQuantumSecurityLevel"] = info.nist_quantum_level
    if f.params:
        if f.family in ("ECC", "ECDSA", "ECDH"):
            alg["curve"] = f.params[0]
        alg["parameterSetIdentifier"] = ",".join(f.params)
    occ = []
    for e in f.evidence[:12]:
        o = {"location": f"{e.region}:{'0x%08x' % e.address if e.address is not None else 'trailer'}",
             "additionalContext": f"[{e.rule}] {e.detail}"[:500]}
        occ.append(o)
    pri, why = PRIORITY.get(f.family, (5, ""))
    props = [_prop("quantumVulnerable", str(info.quantum_vulnerable).lower()),
             _prop("risk", info.risk),
             _prop("migrationPriority", pri),
             _prop("priorityReason", why),
             _prop("classicalStatus", info.classical_status),
             _prop("recommendedReplacement", info.replacement),
             _prop("executionObserved", f.execution),
             _prop("confidence", f"{f.confidence:.2f}")]
    if f.family in PQC_FAMILIES:
        props.append(_prop("postQuantum", "true"))
    if info.note:
        props.append(_prop("note", info.note))
    for n in notes_for(f.family, f.params):
        props.append(_prop("pqcCostNote", n))
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": info.name,
        "description": f"{info.name} detected by binary analysis (confidence {f.confidence:.2f})",
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": alg},
        "evidence": {
            "identity": [{"field": "name", "confidence": round(f.confidence, 2), "concludedValue": info.name,
                          "methods": [{"technique": "binary-analysis", "confidence": round(e.confidence, 2),
                                       "value": f"{e.method}:{e.rule}"} for e in f.evidence[:8]]}],
            "occurrences": occ,
        },
        "properties": props,
    }


def _key_component(k, ref, alg_ref):
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": f"{k.algorithm} public key" + (f" ({k.param})" if k.param else ""),
        "description": k.describe(),
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": "public-key", "id": k.fingerprint, "size": k.bits,
                                                "format": k.fmt},
        },
        "evidence": {"occurrences": [{"location": f"{k.region}:{'0x%08x' % k.address if k.address is not None else 'trailer'}",
                                      "additionalContext": f"source={k.source} {k.context}".strip()}]},
        "properties": [_prop("quantumVulnerable", "true"), _prop("source", k.source)],
    }
    if alg_ref:
        comp["cryptoProperties"]["relatedCryptoMaterialProperties"]["algorithmRef"] = alg_ref
    if k.source == "secure-boot-v2":
        comp["properties"].append(_prop("context", "Secure Boot V2 root of trust: the ROM/bootloader verifies every "
                                                   "image against this key; it cannot be replaced in the field "
                                                   "once its digest is burned into eFuse."))
    return comp


def build_cbom(result, tool_name="cbomscan"):
    fw = result.firmware
    serial = f"urn:uuid:{uuid.uuid4()}"
    fw_ref = "firmware"
    project = fw.app_desc.get("project_name") or "esp32-firmware"
    comps = []
    deps = []
    refs = {}
    order = sorted((f for f in result.findings.values() if f.present),
                   key=lambda f: (PRIORITY.get(f.family, (9,))[0], -f.confidence))
    for f in order:
        ref = f"crypto-algorithm-{f.family.lower()}"
        refs[f.family] = ref
        comps.append(_algorithm_component(f, ref))
    for i, k in enumerate(result.keys):
        fam = "RSA" if k.algorithm == "RSA" else ("ECDSA" if k.source == "secure-boot-v2" else "ECC")
        if k.algorithm in ("X25519",):
            fam = "ECDH"
        comps.append(_key_component(k, f"crypto-key-{i}", refs.get(fam)))
    for lib in result.libraries:
        comps.append({"type": "library", "bom-ref": f"lib-{lib.lower().replace(' ', '-')}", "name": lib,
                      "evidence": {"identity": [{"field": "name", "confidence": 0.5,
                                                 "methods": [{"technique": "binary-analysis", "confidence": 0.5,
                                                              "value": "string-match"}]}]}})
    deps.append({"ref": fw_ref, "dependsOn": [c["bom-ref"] for c in comps]})
    meta_props = [_prop("container", fw.container), _prop("chip", fw.chip),
                  _prop("segments", ", ".join(f"{s.region}@0x{s.addr:08x}+{len(s.data)}" for s in fw.segments)),
                  _prop("ruleGroups", ",".join(result.groups)), _prop("threshold", result.threshold),
                  _prop("pqcCostSource", ESP_PQC_SOURCE)]
    if fw.app_desc:
        meta_props += [_prop("appVersion", fw.app_desc.get("version", "")),
                       _prop("idfVersion", fw.app_desc.get("idf_ver", ""))]
    for n in PLATFORM_NOTES:
        meta_props.append(_prop("platformNote", n))
    for n in fw.notes:
        meta_props.append(_prop("inputNote", n))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            "tools": {"components": [{"type": "application", "name": tool_name, "version": __version__}]},
            "component": {"type": "firmware", "bom-ref": fw_ref, "name": project,
                          "version": fw.app_desc.get("version", "unknown"),
                          "hashes": [{"alg": "SHA-256", "content": fw.sha256}]},
            "properties": meta_props,
        },
        "components": comps,
        "dependencies": deps,
    }

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cbomscan.api import scan_to_dict

PICKS = [
    ("m36rom__Os__full_stack__sbv2_rsa3072", "full stack · signed RSA-3072", "Full stack"),
    ("m36rom__Os__full_stack__sbv2_ecdsa_p256", "full stack · signed ECDSA P-256", "Full stack"),
    ("m36__O2__ota_ecdsa_p256", "OTA with ECDSA P-256", "OTA update"),
    ("m36__O2__ota_rsa_pss", "OTA with RSA-PSS", "OTA update"),
    ("m36__O2__tls_ecdhe_p256_gcm", "TLS ECDHE P-256 + GCM", "TLS"),
    ("m228__O2__x25519_chachapoly", "X25519 + ChaCha20-Poly1305", "TLS"),
    ("m228__O0__legacy_md5_sha1_3des_rsa", "legacy MD5, SHA-1, 3DES, RSA", "Legacy"),
    ("m36__Os__hwaccel_ecdsa_p384", "hardware accelerated ECDSA P-384", "Hardware"),
    ("m36__O2__symmetric_only", "AES and SHA only", "Symmetric"),
    ("m36__O2__noncrypto", "no cryptography", "Control"),
]


def main(out):
    samples, results = [], {}
    for name, label, group in PICKS:
        path = ROOT / "dataset" / "out" / "samples" / name / "firmware.bin"
        if not path.exists():
            print("skip", name)
            continue
        samples.append({"sample": name, "label": label, "group": group})
        results[name] = scan_to_dict(path, name)
    page = (ROOT / "cbomscan" / "dashboard" / "index.html").read_text()
    data = json.dumps({"samples": samples, "results": results}, separators=(",", ":"))
    page = page.replace("const EMBEDDED = null;", "const EMBEDDED = " + data + ";", 1)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(page)
    print(f"wrote {out} with {len(samples)} samples, {len(page) // 1024} KB")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "docs" / "dashboard-demo.html"))

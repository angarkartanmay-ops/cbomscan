"""Migration priority and published PQC cost figures for ESP32-class devices.

Phase I attaches published numbers as context only. It does not claim that a given
image can or cannot fit a replacement; that model is Phase III work.
"""

ESP_PQC_SOURCE = "https://developer.espressif.com/blog/2026/10/esp32-post-quantum-cryptography/"

PQC_COSTS = {
    "ML-DSA-65": {"public_key_bytes": 1952, "signature_bytes": 3309,
                  "verify_ms": "~22 ms (FreeRTOS task) / ~44 ms (2nd-stage bootloader), ESP32-C5 @ 80 MHz",
                  "boot_overhead": "~78 ms extra boot time and 8 KB extra flash for hybrid Secure Boot (12 KB total signature footprint)",
                  "source": ESP_PQC_SOURCE},
    "X25519MLKEM768": {"key_share_bytes": 1216, "handshake": "~300 ms hybrid TLS 1.3 handshake on ESP32-C5 (local network)",
                       "note": "Larger mbedTLS I/O buffers needed for ~1.9 KB keys and ~7.5 KB certificate chains",
                       "source": ESP_PQC_SOURCE},
}

PLATFORM_NOTES = [
    "Espressif esp-pqc needs ESP-IDF v6.0 or later.",
    "Post-quantum bootloader verification in esp-pqc supports ESP32-C3, ESP32-C5 and ESP32-C6 only; "
    "the ROM verifier on every current chip is classical (RSA-PSS / ECDSA) and cannot be patched.",
    "Hybrid Secure Boot keeps the ROM's classical check of the 2nd-stage bootloader; the post-quantum check "
    "runs in the updatable bootloader.",
]

PRIORITY = {
    "ECDH": (1, "Key agreement: traffic recorded today can be decrypted later (harvest now, decrypt later)."),
    "FFDH": (1, "Key agreement: traffic recorded today can be decrypted later (harvest now, decrypt later)."),
    "RSA": (2, "Signatures / key transport: forgery of firmware or identity once a quantum computer exists; "
               "RSA key transport is also exposed to harvest now, decrypt later."),
    "ECDSA": (2, "Signatures: forgery of firmware or identity once a quantum computer exists."),
    "ECC": (2, "Curve arithmetic present; operation not identified, treat as key agreement until shown otherwise."),
    "MD5": (3, "Classically broken; fix regardless of quantum."),
    "SHA1": (3, "Classically broken for signatures; fix regardless of quantum."),
    "DES": (3, "Classically weak; fix regardless of quantum."),
    "AES": (4, "Symmetric: Grover only halves key strength; prefer 256-bit keys."),
    "CHACHA20": (5, "No action."),
    "POLY1305": (5, "No action."),
    "SHA256": (5, "No action (SHA-384 for CNSA 2.0)."),
    "SHA512": (5, "No action."),
}


def notes_for(family, findings_params):
    out = []
    if family in ("RSA", "ECDSA", "ECC"):
        c = PQC_COSTS["ML-DSA-65"]
        out.append(f"ML-DSA-65 sizes: public key {c['public_key_bytes']} B, signature {c['signature_bytes']} B "
                   f"(vs ~64 B for ECDSA-P256). Verify {c['verify_ms']}.")
    if family in ("ECDH", "FFDH", "ECC"):
        c = PQC_COSTS["X25519MLKEM768"]
        out.append(f"X25519MLKEM768 key share {c['key_share_bytes']} B (vs 32 B for X25519); {c['handshake']}. {c['note']}.")
    return out

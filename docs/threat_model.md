# Threat model

## Assets on an ESP32 that depend on public-key cryptography

| Asset | Mechanism today | Breaks if | Consequence |
|---|---|---|---|
| Firmware authenticity at boot | Secure Boot V2: ROM verifies the bootloader, bootloader verifies the app (RSA-3072-PSS or ECDSA P-256/P-384). The eFuse holds a SHA-256 digest of the public key; the key itself is in every signed image's signature block. | The signing private key can be derived from that public key (Shor) | Attacker signs firmware every device accepts. The ROM verifier and burned eFuse digests cannot be changed in the field. |
| OTA update authenticity | App-level signature check, often ECDSA or RSA via mbedTLS | Same | Malicious OTA pushed to the fleet |
| Device identity | mTLS client certificate (ECDSA P-256 or RSA-2048) | Private key derived from the certificate's public key | Cloned or spoofed devices, fake telemetry, forged commands |
| Session confidentiality | TLS key agreement (ECDHE, X25519, sometimes FFDH) | Discrete log solved for recorded handshakes | Recorded traffic decrypted later (harvest now, decrypt later). This is exposed today. |
| Bulk encryption and hashing | AES, ChaCha20, SHA-2 | Not broken by Shor; Grover roughly halves symmetric key strength | Low risk; prefer 256-bit keys for long-lived secrets |

## Adversary

- Records network traffic now and has, at some unknown future date, a cryptographically
  relevant quantum computer (CRQC). Resource estimates for RSA-2048 fell from about 20 million
  physical qubits (2019) to under one million (Gidney, 2025), with architecture papers claiming
  fewer; ECC-256 needs far fewer gates than RSA-2048. No such machine exists today.
- Can obtain any firmware image (OTA server, flash dump) and any public key or certificate.
- Does not need physical access for the OTA and identity attacks.

## Policy clock

NIST IR 8547 (draft) proposes deprecating 112-bit quantum-vulnerable public-key algorithms
(RSA-2048, P-256) after 2030 and disallowing all of them after 2035. Devices shipped today with
10 to 15 year lifetimes fall inside that window.

## Why an inventory comes first

Migration (ML-KEM, ML-DSA, LMS/XMSS, hybrids) requires knowing where RSA, ECC and DH live in
each deployed image. Vendors often do not have source for every component, and deployed
firmware is compiled, stripped and optimised, so source-level tools miss it. cbomscan works on
the binary.

## Out of scope for this project

- Breaking any cryptography, or running quantum algorithms.
- Side-channel and fault attacks on the PQC implementations.
- Proving that a detected algorithm is actually executed at runtime (we report linked capability).

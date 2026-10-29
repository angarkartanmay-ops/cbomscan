# cbomscan report: full_stack

- Input: `dataset/out/samples/m36rom__Os__full_stack__sbv2_rsa3072/firmware.bin` (app-image, 167936 bytes, SHA-256 `ca85cc7c33505f58...`)
- Chip: ESP32; entry 0x40080008; 4 loaded segments
- App: full_stack 1.0.0, ESP-IDF v6.0-sim
- Rule groups: constants, oid, keys, strings, names, hw, secure-boot; decision threshold 0.5

## Summary

**4 quantum-vulnerable public-key families found: Finite-field Diffie-Hellman, Elliptic-curve arithmetic, RSA, ECDSA.**
Secure Boot V2 root of trust uses **RSA PSS public key (3072-bit, Secure Boot V2 signature block, block 0, CRC ok)**: classical, so a quantum-capable attacker who recovers the signing key could sign firmware this device accepts.

## Findings (sorted by migration priority)

| Priority | Algorithm | Quantum | NIST QL | Confidence | Params | Execution | First evidence | Replace with |
|---|---|---|---|---|---|---|---|---|
| 1 | Finite-field Diffie-Hellman | VULNERABLE | 0 | 0.92 | - | software | 0x3f40674a (DROM) | ML-KEM-768 (FIPS 203), hybrid during transition. |
| 2 | Elliptic-curve arithmetic | VULNERABLE | 0 | 0.99 | Curve25519, P-256, P-384 | software | 0x3f405660 (DROM) | Identify the operation (ECDSA or ECDH) and migrate per that row. |
| 2 | RSA | VULNERABLE | 0 | 0.99 | PSS | software | image-trailer | Signatures: ML-DSA-65 (FIPS 204), or LMS/XMSS (SP 800-208) for firmware signing, hybrid with RSA during transition. Key transport: ML-KEM-768 (FIPS 203). |
| 2 | ECDSA | VULNERABLE | 0 | 0.67 | - | software | 0x3f403135 (DROM) | ML-DSA-44/65 (FIPS 204), hybrid ECDSA+ML-DSA during transition; LMS/XMSS for firmware signing. |
| 3 | MD5 | safe | 0 | 0.99 | - | software | 0x400d017c (IROM) | Replace with SHA-256 or SHA-3 (classically broken). |
| 3 | DES / 3DES | safe | 0 | 0.98 | - | software | 0x3f402ac8 (DROM) | Replace with AES-256 (classical weakness, independent of quantum). |
| 3 | SHA-1 | safe | 0 | 0.85 | - | software | 0x400d027c (IROM) | Replace with SHA-256 or SHA-3 (classically broken for signatures). |
| 4 | AES | safe | 1 | 0.99 | - | software+hardware | 0x3f402248 (DROM) | Keep AES; prefer AES-256 for data that must stay secret past ~2035 (Grover margin). |
| 5 | SHA-256 | safe | 2 | 0.99 | - | software+hardware | 0x3f403bc8 (DROM) | Keep; SHA-384 if CNSA 2.0 compliance is required. |
| 5 | SHA-384/512 | safe | 4 | 0.99 | - | software | 0x3f403cc8 (DROM) | Keep. |
| 5 | ChaCha20 | safe | 5 | 0.99 | - | software | 0x400d0098 (IROM) | Keep (256-bit key). |

## Below threshold (weak evidence, not reported as present)

- ECDH / X25519 (0.40): name.ecdh (0.40): algorithm name string 'X25519' (library metadata table)
- Poly1305 (0.40): name.poly1305 (0.40): algorithm name string 'CHACHA20-POLY1305' (library metadata table)

## Key material

- RSA public key (3072-bit, DER SPKI) at 0x3f406548 (DROM); fingerprint 4a17170a7fee6f31
- EC P-256 public key (256-bit, DER SPKI) at 0x3f4066ee (DROM); fingerprint 4bbea5dc2c32eb58
- EC P-384 public key (384-bit, DER SPKI) at 0x3f40684a (DROM); fingerprint c5b33e5ac921a7d7
- RSA PSS public key (3072-bit, Secure Boot V2 signature block, block 0, CRC ok) at image-trailer; fingerprint e811bf5b0b42bfa4

## Evidence detail

### Finite-field Diffie-Hellman
Why it matters: Key agreement: traffic recorded today can be decrypted later (harvest now, decrypt later).
- ffdh.modp (0.92): RFC 2409/3526 MODP group prime (prefix); 1/3 pattern(s) matched; referenced from code at 0x400d0624

### Elliptic-curve arithmetic
Why it matters: Curve arithmetic present; operation not identified, treat as key agreement until shown otherwise.
- ecc.p256 (0.99): NIST P-256 (secp256r1) domain parameters; 4/8 pattern(s) matched; referenced from code at 0x400d03f0, 0x400d03f4, 0x400d0404
- ecc.p384 (0.99): NIST P-384 (secp384r1) domain parameters; 2/4 pattern(s) matched; referenced from code at 0x400d0408, 0x400d0410, 0x400d0414
- ecc.x25519_order (0.92): Curve25519 group order (low part); 1/2 pattern(s) matched; referenced from code at 0x400d0424, 0x400d042c, 0x400d0430
- key.ec (0.85): embedded EC P-256 public key (256-bit, DER SPKI)
- key.ec (0.85): embedded EC P-384 public key (384-bit, DER SPKI)
- ecc.x25519_p (0.77): Curve25519 field prime 2^255-19; 1/2 pattern(s) matched; referenced from code at 0x400d0424, 0x400d042c
- ecc.x25519_a24 (0.50): Curve25519 Montgomery ladder constant a24; 1/2 distinct constants found
- oid.ec_pubkey (0.42): id-ecPublicKey OID (1.2.840.10045.2.1); 1/1 pattern(s) matched; referenced from code at 0x400d0618

### RSA
Why it matters: Signatures / key transport: forgery of firmware or identity once a quantum computer exists; RSA key transport is also exposed to harvest now, decrypt later.
- sbv2.rsa (0.99): Secure Boot V2 signature block: RSA PSS public key (3072-bit, Secure Boot V2 signature block, block 0, CRC ok)
- key.rsa (0.85): embedded RSA public key (3072-bit, DER SPKI)
- oid.rsa (0.47): rsaEncryption OID (1.2.840.113549.1.1.1); 1/1 pattern(s) matched; referenced from code at 0x400d0318, 0x400d0618
- oid.rsa_pss (0.45): RSASSA-PSS OID (1.2.840.113549.1.1.10); 1/1 pattern(s) matched
- name.rsa (0.40): algorithm name string 'RSA' (library metadata table)
- str.begin_rsa_public_key (0.35): string '-----BEGIN RSA PUBLIC KEY-----'

### ECDSA
Why it matters: Signatures: forgery of firmware or identity once a quantum computer exists.
- oid.ecdsa (0.45): ecdsa-with-SHA256/384 OID; 2/2 pattern(s) matched
- name.ecdsa (0.40): algorithm name string 'ECDSA' (library metadata table)

### MD5
Why it matters: Classically broken; fix regardless of quantum.
- md5.t (0.99): MD5 sine-derived round constants (as literal-pool or table words); 64/64 distinct constants found
- md5.t_table (0.97): MD5 constant table; 1/1 pattern(s) matched

### DES / 3DES
Why it matters: Classically weak; fix regardless of quantum.
- des.sp_boxes (0.97): DES combined S/P tables (d3des layout); 8/8 pattern(s) matched; referenced from code at 0x400d0088
- name.des (0.40): algorithm name string 'DES-EDE3-CBC' (library metadata table)

### SHA-1
Why it matters: Classically broken for signatures; fix regardless of quantum.
- sha1.k (0.85): SHA-1 round constants and fifth IV word; 5/5 distinct constants found

### AES
Why it matters: Symmetric: Grover only halves key strength; prefer 256-bit keys.
- aes.sbox (0.97): AES forward S-box; 1/1 pattern(s) matched; referenced from code at 0x400d002c
- aes.inv_sbox (0.97): AES inverse S-box; 1/1 pattern(s) matched; referenced from code at 0x400d0050
- aes.te_table (0.97): AES encryption T-table (Te/FT); 2/4 pattern(s) matched; referenced from code at 0x400d0040
- aes.td_table (0.97): AES decryption T-table (Td/RT); 2/4 pattern(s) matched; referenced from code at 0x400d0030
- hw.aes (0.85): ESP32 AES accelerator registers: 7 code references to 7 register(s) (0x3ff01000, 0x3ff01004, 0x3ff01008, 0x3ff01010...)
- aes.rcon (0.72): AES key-schedule round constants; 1/2 pattern(s) matched; referenced from code at 0x400d0028, 0x400d0034
- name.aes (0.40): algorithm name string 'AES-256-GCM' (library metadata table)

### SHA-256
Why it matters: No action (SHA-384 for CNSA 2.0).
- sha256.k (0.99): SHA-256 round-constant table K[0..31]; 1/2 pattern(s) matched; referenced from code at 0x400d02d0
- hw.sha256 (0.85): ESP32 SHA accelerator registers: 7 code references to 7 register(s) (0x3ff03000, 0x3ff03020, 0x3ff03040, 0x3ff03090...)
- sha256.iv (0.25): SHA-256/224 initial hash values; 16/16 distinct constants found; discounted: every SHA-256/224 IV word is also half of a SHA-512/384 IV, and SHA-512 is present

### SHA-384/512
Why it matters: No action.
- sha512.k (0.99): SHA-512 round-constant table K[0..11]; 1/2 pattern(s) matched; referenced from code at 0x400d0314
- sha512.iv (0.84): SHA-512/384 initial hash values (32-bit halves not shared with SHA-256/224 IVs); 16/16 distinct constants found

### ChaCha20
Why it matters: No action.
- chacha20.sigma (0.90): ChaCha20 'expand 32-byte k' constants; 4/4 distinct constants found
- chacha20.sigma_str (0.90): ChaCha20/Salsa20 sigma string; 1/1 pattern(s) matched
- name.chacha20 (0.40): algorithm name string 'CHACHA20-POLY1305' (library metadata table)

## Platform notes

- Espressif esp-pqc needs ESP-IDF v6.0 or later.
- Post-quantum bootloader verification in esp-pqc supports ESP32-C3, ESP32-C5 and ESP32-C6 only; the ROM verifier on every current chip is classical (RSA-PSS / ECDSA) and cannot be patched.
- Hybrid Secure Boot keeps the ROM's classical check of the 2nd-stage bootloader; the post-quantum check runs in the updatable bootloader.

## Known Phase I limits

- Rules cannot yet tell ECDSA from ECDH when both share curve code; ECC is reported with the curve.
- AES with run-time generated tables (mbedTLS default) leaves no constants; only hardware use or tables are found.
- Poly1305 masks are often folded into shift instructions by the compiler.
- Presence means the code is linked into the image, not that it runs on a given path.

# Phase I report: rule-based CBOM generation for stripped ESP32 firmware

## 1. Goal of Phase I

Build the end-to-end pipeline and the measurement setup that Phase II will improve on:
parse ESP32 firmware, detect cryptography with deterministic rules, classify quantum risk,
emit a valid CycloneDX CBOM, and measure accuracy against ground truth on a labelled dataset.

## 2. What was built

1. **Labelled dataset** (`dataset/`). 11 application profiles that use crypto the way real IoT
   firmware does (RSA-PSS OTA verification, ECDSA OTA verification, ECDHE + AES-GCM TLS-style
   session, X25519 + ChaCha20-Poly1305, legacy MD5/SHA-1/3DES/RSA, FFDH + AES-CBC, symmetric only,
   hardware-accelerated SHA/AES + ECDSA P-384, RSA device identity, everything combined, and a
   no-crypto control). Each is linked with mbedTLS and non-crypto filler code (miniz compression,
   jsmn JSON parser, printf, application logic), built 12 ways: mbedTLS 3.6.7 (AES tables
   generated at run time, the default), mbedTLS 3.6.7 with AES tables in flash, and mbedTLS
   2.28.10, each at -O0, -O1, -O2, -Os. Output is a real ESP32 app image (esptool `image-info`
   reads it, including the app descriptor). The Os builds are also signed with Secure Boot V2
   (RSA-3072 and ECDSA P-256), giving 198 images.
2. **Ground truth from the linker map.** Every byte of the image is attributed to the object file
   it came from, so truth is "this algorithm's code is linked into the image". This is capability,
   which is what a CBOM records; it is not proof the code runs.
3. **Scanner** (`cbomscan/`). Parses app images, flash dumps (partition table) and stripped ELF;
   recovers the Secure Boot V2 signature block; runs seven rule groups; combines evidence per family
   with a noisy-OR; reports present families above a 0.5 threshold.
4. **CBOM + reports.** CycloneDX 1.6 JSON with `nistQuantumSecurityLevel`, evidence occurrences
   (address and region), key material as `related-crypto-material`, migration priority and NIST
   replacement as properties. Every CBOM is validated against the official 1.6 schema.
5. **Evaluation harness** with a strings-only baseline (what string-matching firmware tools do)
   and rule-group ablations.

## 3. Results (132 unsigned images, 13 families, image-level detection)

| System | Precision | Recall | F1 |
|---|---|---|---|
| Strings-only baseline | 0.86 | 0.80 | 0.83 |
| Rules: constants only | 1.00 | 0.72 | 0.84 |
| Rules: + OIDs | 1.00 | 0.78 | 0.88 |
| Rules: + keys, strings, hardware registers | 1.00 | 0.80 | 0.89 |
| Rules: all (+ algorithm-name strings) | **1.00** | **0.86** | **0.93** |

![Per-family F1](../results/f1_by_family.png)

- **No false positives** in any rule configuration, including the no-crypto control images.
- **Perfect** on DES, ChaCha20, MD5, SHA-1, SHA-256, SHA-384/512, RSA, ECDSA, EC arithmetic and
  finite-field DH.
- **Quantum-vulnerable classes:** RSA, ECC and FFDH each at precision 1.00 / recall 1.00; the
  strings baseline gets ECC at 0.75 precision and FFDH at 0.25 recall. Image-level "contains
  quantum-vulnerable public-key crypto": 108/108 found, 0/24 false alarms.
- **Secure Boot V2:** 66/66 signature blocks decoded with the right scheme, key size and curve.
  This is the root-of-trust finding the threat model cares most about.
- **Optimisation level barely matters for these rules** (F1 0.93 at every level), because most
  rules read data tables and literal pools, not instruction sequences.
- Scan time: about 45 ms per image in pure Python.

## 4. Where the rules fail, and why (Phase II targets)

| Gap | Recall | Cause found in the binaries |
|---|---|---|
| ECDH | 0.00 | ECDH and ECDSA share all curve code and constants. The rules see the curve (P-256, P-384, Curve25519) but cannot tell which operation uses it. |
| AES (default mbedTLS) | 0.46 overall | mbedTLS builds its AES tables in RAM at boot by default, so the flash image holds no S-box. Detection only works when tables are in flash or the hardware accelerator is used. |
| Poly1305 | 0.08 | The compiler turned `& 0x0FFFFFFF` into a shift pair (`slli 4; srli 4`), so one of the two clamp constants never appears in the binary. |

All three are cases where the evidence is in the **instructions**, not the data, which is exactly
what the Phase II function-level ML classifier is for.

## 5. Things the evaluation taught us

- **Library metadata is not code.** Curve names and OIDs live in lookup tables that a certificate
  parser links even when the curve arithmetic is not linked. Using curve-name strings as ECC
  evidence produced 24 false positives on RSA-only images, so they were removed.
- **Shared constants mislead.** Every SHA-256 and SHA-224 IV word is also half of a SHA-512/384 IV.
  Checking *where* evidence lands (not just whether a family is detected) exposed a rule that
  matched SHA-384 constants inside SHA-256 code. The image-level score could not catch it because
  every image with SHA-256 here also links SHA-512. The rule was fixed.
- **Capability is broad.** One OTA verification call links RSA, ECDSA, DES, MD5 and more through
  mbedTLS's PK, PEM and MD layers. A firmware CBOM will list far more algorithms than the
  developer thinks they use, which is itself a useful finding to report.

## 6. Threats to validity (state these to the evaluators)

1. **In-distribution evaluation.** The rules were developed while looking at this dataset
   (three rule decisions above came from its errors). The numbers are an upper bound. Phase II
   must test on held-out builds: a different library (wolfSSL), a different toolchain, and real
   vendor firmware.
2. **Toolchain.** Images were built with Ubuntu's Xtensa GCC 13.2 for the LX106 core (call0 ABI),
   linked with an ESP32 memory map. Real ESP32 firmware uses Espressif's GCC and the windowed ABI.
   The data-oriented Phase I rules are unaffected; instruction-level work in Phase II must use
   images rebuilt with ESP-IDF's `xtensa-esp32-elf-gcc` (the build script takes the toolchain as
   a parameter).
3. **One library.** All crypto comes from mbedTLS. Spec-derived constants should transfer;
   name-string and OID rules are more library-specific.
4. **Hardware accelerator registers** are modelled on the ESP32 TRM peripheral map and exercised
   only by a synthetic driver; ESP32-S/C/P series use different addresses (not yet covered).
5. **Truth is linked capability**, not runtime use.

## 7. Phase II plan (proposed)

1. Rebuild the dataset with ESP-IDF's toolchain; add wolfSSL and at least 3 real ESP-IDF example
   apps as a held-out test set.
2. Function boundary recovery for stripped Xtensa code (ENTRY instructions in the windowed ABI,
   call targets), then per-function features (instruction n-grams, constant and loop features).
3. Train a function-level classifier for the three gaps: ECDSA vs ECDH, run-time-table AES,
   Poly1305; report rules vs rules+ML, with the held-out set.

## 8. How to reproduce

See `README.md`. `python eval/evaluate.py` regenerates every number in this report from the
dataset; `python -m pytest -q tests` runs the 18 tests.

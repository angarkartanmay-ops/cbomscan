# cbomscan: a Cryptography Bill of Materials for compiled ESP32 firmware

III Semester Experiential Learning project, Department of CSE, RV College of Engineering, Bengaluru.
Final report draft (P3.4), 9 November 2026. Every figure links to the file it comes from.

## 1. Problem

ESP32 devices stay deployed for 10 to 15 years. Their trust rests on RSA and elliptic-curve cryptography:
Secure Boot V2 signature checks, OTA update verification, device certificates and TLS key exchange. Shor's
algorithm breaks both on a large quantum computer, and NIST's draft IR 8547 deprecates them after 2030 and
disallows them after 2035 ([background_research.md](background_research.md)). Key exchange is exposed today,
because recorded traffic can be decrypted later.

Migration starts with an inventory. A team cannot replace RSA in a device until it knows where RSA is. Deployed
IoT firmware is shipped as compiled, stripped binaries, often without source.

**Research question.** Can the cryptographic algorithms in a compiled, stripped ESP32 firmware image be
identified accurately enough to produce a usable Cryptography Bill of Materials, with quantum risk and a
migration plan, without source code?

## 2. Related work and the gap

- **CBOMkit** (IBM) and **cryptoscan-pqc** produce CBOMs from source code or repositories.
- **IIFVDCAS** analyses ESP32/Arduino binaries but builds its CBOM from strings only, and does not classify RSA or
  ECC found in code by quantum risk.
- **FoC** identifies crypto functions in stripped binaries with a language model; it is not specific to Xtensa or
  ESP32 image formats.

No public tool found during the research combines (a) ESP32 image parsing, (b) detection in stripped Xtensa code,
and (c) a CycloneDX CBOM with quantum risk and migration feasibility. Sources:
[background_research.md](background_research.md), section 5.

## 3. What was built

```
firmware.bin / flash dump / ELF
  -> image parser (segments, app descriptor, partition table, Secure Boot V2 block)
  -> Tier 1 rules: spec-derived constants, OIDs, embedded keys, names, accelerator registers, PQC tables
  -> Tier 2 (optional, --ml): function recovery -> features -> gradient-boosted function classifier
  -> evidence combined per family -> quantum risk, priority, NIST replacement
  -> feasibility checks for each migration action
  -> CycloneDX 1.6 CBOM (schema-validated), Markdown/HTML report, Cryptolens dashboard
```

| Part | Where | Doc |
|---|---|---|
| Image parser, Secure Boot V2 decoder | `cbomscan/image.py`, `keys.py` | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Tier 1 rules (13 classical families) | `cbomscan/signatures.py`, `detect.py` | [PHASE1_REPORT.md](PHASE1_REPORT.md) |
| Post-quantum rules (ML-KEM, ML-DSA, LMS) | `signatures.py` | [PQC_RULES.md](PQC_RULES.md) |
| Disassembly, function recovery, features | `disasm.py`, `functions.py`, `mlfeatures.py` | [DISASM.md](DISASM.md), [FUNCTIONS.md](FUNCTIONS.md) |
| Tier 2 classifier | `cbomscan/ml.py`, `eval/phase2_ml.py` | [PHASE2_ML.md](PHASE2_ML.md) |
| Feasibility and chip scope | `cbomscan/feasibility.py` | [FEASIBILITY.md](FEASIBILITY.md), [CHIPS.md](CHIPS.md) |
| CBOM export | `cbomscan/cbom.py`, `validate.py` | |
| Dashboard | `cbomscan/dashboard/`, `server.py` | README, "Dashboard" |

## 4. Data

| Set | Images | Built with | Use |
|---|---|---|---|
| Phase I | 198 (132 + 66 Secure Boot signed) | Ubuntu Xtensa GCC (call0 ABI), mbedTLS 2.28 / 3.6 | rule development |
| ESP32 rebuild | 231 | Espressif GCC 16.1 (windowed ABI) | rule check, ML training (41,051 labelled functions) |
| Post-quantum | 45 | Espressif GCC 16.1; PQClean, mlkem-native, mldsa-native, hash-sigs | PQC rules, feasibility sizes |
| **Held-out** | **32** | ESP-IDF v5.5.6; mbedTLS and wolfSSL apps | **scoring only**, frozen by SHA-256 manifest |

Truth comes from linker maps: a family is present when its code or data is linked
([DATASET.md](DATASET.md), [HELDOUT.md](HELDOUT.md)).

## 5. Results

Scores are image-level family detection, micro-averaged over 13 families.

### 5.1 Development data (rules were tuned here)

Rules: precision 1.00, recall 0.86, F1 0.93 on both the Phase I and the Espressif rebuild
([results/RESULTS.md](../results/RESULTS.md), [results/esp32/RESULTS.md](../results/esp32/RESULTS.md)).
These are upper bounds.

### 5.2 Held-out set

| System (32 held-out images) | Precision | Recall | F1 |
|---|---|---|---|
| Strings baseline | 0.93 | 0.98 | 0.95 |
| Rules | 1.00 | 0.82 | 0.90 |
| ML alone | 0.85 | 0.79 | 0.82 |
| Rules + ML | 0.86 | 0.92 | 0.89 |

Sources: [results/heldout/RESULTS.md](../results/heldout/RESULTS.md),
[results/phase2/RESULTS_phase2.md](../results/phase2/RESULTS_phase2.md). The ML tier was trained on development
images only, k was chosen by development cross-validation, and the held-out set was predicted once.

- **Rules keep their precision** on a new compiler, build system and library (0.996), but recall drops from 0.86
  to 0.82. With the MD5 truth defect excluded, rules recall is 0.86 (post-hoc).
- **ML finds ECDH for the first time** (13 of 32 images, no false positives), which no rule can, because ECDH
  shares all its constants with ECDSA.
- **ML adds false positives**: 49 against the rules' 1, mostly Poly1305 (24), DES (16) and ChaCha20 (8). Precision falls to
  0.86, below the 0.95 goal set in the roadmap.
- **The strings baseline wins on this set** because both libraries embed algorithm names. It would not on
  firmware built without those strings.

### 5.3 Post-quantum detection

ML-KEM 10 of 10 images, ML-DSA 10 of 10, LMS 20 of 25 (the 5 misses read the key from flash at run time). No
false positives on the 198 Phase I images ([results/RESULTS_pqc.md](../results/RESULTS_pqc.md)).

### 5.4 Feasibility example

On the signed full-stack ESP32 image, moving signatures to ML-DSA-65 fits in flash (82% of a 1 MB partition free
after), but is **blocked** for the boot chain: esp-pqc's post-quantum boot verification supports ESP32-C3, C5 and
C6 only, and every chip's ROM verifier stays classical ([FEASIBILITY.md](FEASIBILITY.md)).

## 6. Limitations

- **Truth is linked capability**, not run-time use. On the held-out set it overstates MD5 in 16 mbedTLS images
  ([results/heldout/ANALYSIS.md](../results/heldout/ANALYSIS.md)); the frozen files were not edited.
- **The held-out set is narrow:** two libraries, one ESP-IDF version, no ChaCha20, Poly1305 in 4 images.
- **Library strings help the baseline:** both libraries embed algorithm names, so the strings baseline does well
  on this set. Vendor firmware built without such strings would not.
- **Function recovery** was tuned and measured on development images (precision 1.000, recall 0.987).
- **Chips:** measured on ESP32 only. Data rules should transfer; register rules and the ML tier do not
  ([CHIPS.md](CHIPS.md)).
- **LMS rule false positive:** a small-integer table matched the LMS rule in 12 of 16 wolfSSL held-out images. It
  was fixed from the RFC 8554 key format, and the held-out set can no longer test that fix independently
  ([PQC_RULES.md](PQC_RULES.md)).
- **No hardware test:** the board script has been rehearsed on a synthetic flash dump only
  ([BOARD_TEST.md](BOARD_TEST.md)).
- **Feasibility is static:** RAM and AES key length cannot be read from an image.

## 7. Conclusion

A rule engine built from specification constants identifies the cryptography in compiled ESP32 firmware with
near-perfect precision on unseen builds (0.996 on the held-out set) and turns it into a schema-valid CycloneDX
CBOM with quantum risk, NIST replacements and feasibility checks. Its recall gap is structural: ECDH, AES with
run-time tables and Poly1305 leave no distinctive data.

A function classifier closes part of that gap (ECDH found in 13 of 32 held-out images, recall 0.82 to 0.92) but,
trained on one library family, it is not precise enough to switch on by default. The next step is training data
from more libraries and a fresh held-out set, so that per-family acceptance can be chosen and measured cleanly.

For migration planning, the feasibility checks show that on the original ESP32 the boot chain cannot move to
post-quantum signatures with esp-pqc today, while key agreement and OTA verification can, subject to an ESP-IDF
upgrade and a RAM check on the device.

## 8. Reproduce

```bash
pip install -r requirements.txt -r requirements-phase2.txt
python -m pytest -q tests
python eval/evaluate.py                                                    # Phase I
python eval/evaluate.py --dataset dataset/heldout --out results/heldout   # held-out, rules
python eval/phase2_ml.py                                                   # ML tier, scores held-out once
python -m cbomscan serve                                                   # dashboard
```

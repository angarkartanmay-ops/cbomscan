# Roadmap

The project runs in three graded EL phases. Each task below is also a GitHub issue; the issue
holds the discussion, the task here holds the plan. Tick items as PRs merge.

## Phase I: rule-based scanner and measurement setup (complete)

- [x] ESP32 image parser: app images, flash dumps, stripped ELF, app descriptor
- [x] Secure Boot V2 signature block decoder
- [x] Tier 1 rules: constants, literal-pool words, OIDs, embedded keys, name strings, accelerator registers
- [x] Quantum-risk taxonomy, migration priority, replacements
- [x] CycloneDX 1.6 CBOM export with schema validation
- [x] Labelled dataset (198 images) with linker-map ground truth
- [x] Evaluation harness, strings baseline, ablations, tests, CI
- [x] Phase I report

Outcome: micro F1 0.93, precision 1.00 on 132 images; three documented gaps (ECDH, run-time-table
AES, Poly1305). See [PHASE1_REPORT.md](PHASE1_REPORT.md).

## Phase II: instruction-level detection (Tier 2 ML)

The three gaps all have their evidence in instructions, not data. Phase II builds the
instruction-level pipeline and a classifier, and measures it on data the rules were not tuned on.

```
P2.1 Rebuild with ESP-IDF toolchain ─┐
P2.2 Held-out test set ──────────────┼──► P2.5 Function labels ──► P2.6 Features ──► P2.7 Classifier ──► P2.8 Integrate + evaluate
P2.3 Disassembly backend ──► P2.4 Function boundaries ─┘
P2.9 PQC algorithm rules (independent)
```

### P2.1 Rebuild the dataset with Espressif's ESP32 toolchain
Install ESP-IDF on one laptop, run `build_dataset.py --toolchain-prefix xtensa-esp32-elf- --specs ""`.
Fix link issues (newlib instead of picolibc; drop `libgcc_shim.c` if libgcc is complete).
**Done when:** `dataset/out_esp32` holds the same 198 samples, images show windowed-ABI `entry`
instructions, and `eval/evaluate.py --dataset dataset/out_esp32` runs. Compare Phase I rule scores
on both toolchains.

### P2.2 Held-out test set
Never used while writing rules or training. Three sources:
1. wolfSSL builds of the same profiles (different library, different code shape).
2. Real ESP-IDF example apps built with ESP-IDF: `https_request`, `simple_ota_example`,
   `mqtt/ssl`, `secure_boot` examples. Truth from their linker maps.
3. If available and permitted: public vendor firmware images, labelled by hand.
**Done when:** at least 30 held-out images with truth, stored under `dataset/heldout/`, and the
Phase I rules evaluated on them (expect lower numbers; that is the honest baseline).

### P2.3 Xtensa disassembly backend
Options: GNU `objdump -D -b binary -mxtensa` (needs a toolchain), Capstone 6 (has Xtensa), or a
small table-driven decoder in Python for the instruction subset we need.
**Done when:** `cbomscan/disasm.py` returns a list of `(address, size, mnemonic, operands)` for a
code segment and agrees with objdump on the test images.

**Status (branch `phase2`): done for the ESP32 / windowed ABI.** Capstone 6 plus a small own decoder;
99.84 % address+size and 99.46 % mnemonic agreement with objdump over 207 224 instructions; rationale,
residue and limits in [DISASM.md](DISASM.md).

### P2.4 Function boundary recovery in stripped code
Windowed ABI: functions start with `entry`. Call0 ABI: use `call0`/`callx0` targets and
literal-pool function pointers. Ends at the next start.
**Done when:** on unstripped images, recovered starts match symbol-table function starts with
precision and recall above 0.9.

### P2.5 Function-level labels
From the linker map and symbol table of the unstripped ELF: each recovered function gets the
family of the object file it came from (or "non-crypto").
**Done when:** `dataset/functions.parquet` (or JSON) with one row per function: sample, address,
size, family label.

### P2.6 Features
Start simple and interpretable: mnemonic histogram, mnemonic bigrams, counts of shifts/rotates/xor/
mul, loop count, immediate and literal-pool constants, call fan-in/out, size. Optional later:
learned embeddings.
**Done when:** a feature matrix for all functions and a notebook showing class separation for
ECDSA vs ECDH functions.

### P2.7 Classifier
Gradient-boosted trees or random forest first (scikit-learn); split by **sample group** (never put
functions from the same build in train and test). Report per-family precision/recall at function
level and the confusion between ECDSA and ECDH.
**Done when:** trained model file, training script, and results on the held-out set.

### P2.8 Integrate Tier 2 and evaluate
Add Tier 2 evidence (`group="ml"`) to `detect.py` with calibrated confidence. Evaluate rules vs
rules+ML on the held-out set.
**Done when:** `results/RESULTS_phase2.md` with the comparison, and the three gap families improve
without dropping precision below 0.95.

### P2.9 Detect post-quantum algorithms
Migrated firmware must show up correctly in the CBOM. Add constant rules for ML-KEM (q = 3329, NTT
zeta table), ML-DSA (q = 8380417, zeta table), SLH-DSA / SHAKE (Keccak round constants), LMS
(SHA-256 with LMS type codes). Build test images with liboqs or esp-pqc.
**Done when:** the scanner reports ML-KEM / ML-DSA with `nistQuantumSecurityLevel` above 0 on
esp-pqc example builds.

**Status (branch `phase2`):** ML-KEM and ML-DSA done and verified against real bytes of PQClean and
mlkem-native/mldsa-native builds made with Espressif GCC 16.1 (20 images, 10/10 each, no false
positives); LMS public keys detected by structure (20/25; the 5 misses are verifier-only images with
no embedded key, a documented blind spot for tier 2); details and limits in [PQC_RULES.md](PQC_RULES.md).
Not done: SLH-DSA (no constant table; needs tier 2), and esp-pqc example builds (esp-pqc needs ESP-IDF 6.0;
the acceptance criterion above is therefore not yet met as written, only on PQClean/mlkem-native
builds).

## Phase III: migration planning, other chips, demo, write-up

### P3.1 Migration feasibility model
For each finding, estimate whether the replacement fits: flash headroom (partition size minus
image size), RAM for TLS buffers, boot-time budget, chip support (esp-pqc boot verification is
C3/C5/C6 only). Inputs: CBOM + partition table + chip. Output: feasibility per finding, with the
assumptions shown.

### P3.2 More chips
Chip detection from the image header already exists. Add accelerator register windows for
ESP32-S2/S3/C3/C6/C5/P4 from their Technical Reference Manuals, and chip-specific Secure Boot
facts.

### P3.3 Demo (optional)
On an ESP32-C5 or C6: build a classical OTA + TLS app, scan it; migrate with esp-pqc (hybrid TLS
X25519MLKEM768, hybrid boot ML-DSA-65); rescan; show the CBOM diff.

### P3.4 Write-up
Final report and paper draft: problem, related work (CBOMkit, FoC, IIFVDCAS, cryptoscan), method,
dataset, results with the held-out set, limitations.

## Risks

| Risk | Mitigation |
|---|---|
| ESP-IDF toolchain trouble on team laptops | Start P2.1 in week 1; one person owns it |
| Held-out set too small | Use ESP-IDF examples first; they are free and have truth |
| ML adds little over rules | Aim ML only at the three gap families; report it honestly either way |
| Scope creep | P3.3 and the paper are optional until P2.8 is done |

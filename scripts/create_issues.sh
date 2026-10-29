#!/usr/bin/env bash
# Creates the Phase II / III labels and issues from docs/ROADMAP.md.
# Run once from the repo root after `gh auth login`:  ./scripts/create_issues.sh
set -euo pipefail
REPO="${REPO:-angarkartanmay-ops/cbomscan}"

label() { gh label create "$1" --repo "$REPO" --color "$2" --description "$3" --force >/dev/null; }
label "phase-2" "1f6feb" "Phase II: instruction-level detection"
label "phase-3" "8250df" "Phase III: migration planning, chips, demo, write-up"
label "dataset" "0e8a16" "Dataset and ground truth"
label "detection" "d93f0b" "Rules and detection logic"
label "ml" "fbca04" "Tier 2 machine learning"
label "cbom" "5319e7" "CBOM output and migration guidance"
label "docs" "c5def5" "Documentation and write-up"
label "good first issue" "7057ff" "Small, self-contained"

issue() {
  local title="$1" labels="$2" body="$3"
  gh issue create --repo "$REPO" --title "$title" --label "$labels" --body "$body" >/dev/null
  echo "created: $title"
}

issue "P2.1 Rebuild the dataset with Espressif's ESP32 toolchain (windowed ABI)" "phase-2,dataset" \
"Phase I images used Ubuntu's xtensa-lx106-elf GCC (call0 ABI). Instruction-level work needs real ESP32 code (windowed ABI).

\`\`\`bash
. \$IDF_PATH/export.sh
./scripts/fetch_third_party.sh
python dataset/build_dataset.py --toolchain-prefix xtensa-esp32-elf- --specs \"\" --out dataset/out_esp32
python eval/evaluate.py --dataset dataset/out_esp32 --out results_esp32
\`\`\`
Fix link issues (newlib instead of picolibc; drop libgcc_shim.c if libgcc is complete).

**Done when**
- [ ] dataset/out_esp32 has the same 198 samples
- [ ] disassembly shows \`entry\` at function starts
- [ ] Phase I rule scores reported for both toolchains

See docs/ROADMAP.md P2.1."

issue "P2.2 Build a held-out test set (wolfSSL + real ESP-IDF apps)" "phase-2,dataset" \
"Rules were tuned on dataset/out, so Phase I numbers are an upper bound. We need images never used for tuning or training.

Sources:
1. wolfSSL builds of the same profiles
2. ESP-IDF examples built with ESP-IDF: https_request, simple_ota_example, mqtt/ssl, secure_boot (truth from linker maps)
3. Public vendor firmware, hand-labelled, if available and permitted

**Done when**
- [ ] at least 30 held-out images with truth in dataset/heldout/
- [ ] Phase I rules evaluated on them and reported (lower numbers expected)

Depends on P2.1. See docs/ROADMAP.md P2.2."

issue "P2.3 Xtensa disassembly backend" "phase-2,detection" \
"Add cbomscan/disasm.py returning (address, size, mnemonic, operands) for a code segment.
Options: GNU objdump -D -b binary -mxtensa, Capstone 6 (has Xtensa), or a small Python decoder for the needed subset.

**Done when**
- [ ] output agrees with objdump on the test images
- [ ] unit tests

See docs/ROADMAP.md P2.3."

issue "P2.4 Function boundary recovery in stripped Xtensa code" "phase-2,detection" \
"Windowed ABI: functions start with \`entry\`. Call0 ABI: use call0/callx0 targets and literal-pool function pointers. A function ends at the next start.

**Done when**
- [ ] on unstripped images, recovered function starts match symbol-table starts with precision and recall > 0.9

Depends on P2.3. See docs/ROADMAP.md P2.4."

issue "P2.5 Function-level labels from linker maps" "phase-2,dataset,ml" \
"Give each recovered function the family of the object file it came from (or non-crypto), using the linker map and symbol table of the unstripped ELF.

**Done when**
- [ ] one row per function: sample, address, size, family label (dataset/functions.parquet or JSON)

Depends on P2.1, P2.4. See docs/ROADMAP.md P2.5."

issue "P2.6 Per-function features" "phase-2,ml" \
"Start simple and interpretable: mnemonic histogram, mnemonic bigrams, shift/rotate/xor/mul counts, loop count, immediates and literal-pool constants, call fan-in/out, size.

**Done when**
- [ ] feature matrix for all functions
- [ ] notebook showing class separation for ECDSA vs ECDH functions

Depends on P2.5. See docs/ROADMAP.md P2.6."

issue "P2.7 Train the Tier 2 classifier" "phase-2,ml" \
"Random forest or gradient-boosted trees first (scikit-learn). Split by sample group: never put functions from the same build in both train and test.
Targets: ECDSA vs ECDH, AES with run-time tables, Poly1305 (the three Phase I gaps).

**Done when**
- [ ] training script and model file
- [ ] function-level precision/recall per family and ECDSA/ECDH confusion matrix on the held-out set

Depends on P2.2, P2.6. See docs/ROADMAP.md P2.7."

issue "P2.8 Integrate Tier 2 into the scanner and evaluate" "phase-2,ml,detection" \
"Add Tier 2 evidence (group=\"ml\", function address, calibrated confidence) to cbomscan/detect.py. Compare rules vs rules+ML on the held-out set.

**Done when**
- [ ] results/RESULTS_phase2.md with the comparison
- [ ] ECDH, AES and Poly1305 recall improve with precision >= 0.95

Depends on P2.7. See docs/ROADMAP.md P2.8."

issue "P2.9 Detect post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA, LMS)" "phase-2,detection" \
"Migrated firmware must show up correctly in the CBOM. Add constant rules: ML-KEM (q = 3329, NTT zeta table), ML-DSA (q = 8380417, zeta table), SLH-DSA/SHAKE (Keccak round constants), LMS type codes. Build test images with liboqs or Espressif esp-pqc.

**Done when**
- [ ] scanner reports ML-KEM / ML-DSA with nistQuantumSecurityLevel > 0 on esp-pqc example builds
- [ ] tests

Independent of the other P2 tasks. See docs/ROADMAP.md P2.9."

issue "P3.1 Migration feasibility model" "phase-3,cbom" \
"For each finding, estimate whether the replacement fits: flash headroom (partition size minus image size), RAM for TLS buffers, boot-time budget, chip support (esp-pqc boot verification is C3/C5/C6 only). Show assumptions in the CBOM properties and report.

See docs/ROADMAP.md P3.1."

issue "P3.2 Support more chips (ESP32-S2/S3/C3/C6/C5/P4)" "phase-3,detection,good first issue" \
"Chip detection from the image header exists. Add accelerator register windows for each chip from its Technical Reference Manual (cbomscan/signatures.py HW_WINDOWS) and chip-specific Secure Boot facts.

See docs/ROADMAP.md P3.2."

issue "P3.3 Demo: migrate one board with esp-pqc and show the CBOM change" "phase-3" \
"Optional. On an ESP32-C5 or C6: build a classical OTA + TLS app and scan it; migrate with esp-pqc (hybrid TLS X25519MLKEM768, hybrid boot ML-DSA-65); rescan; show the CBOM diff. Needs P2.9.

See docs/ROADMAP.md P3.3."

issue "P3.4 Final report and paper draft" "phase-3,docs" \
"Problem, related work (CBOMkit, FoC, IIFVDCAS, cryptoscan), method, dataset, results including the held-out set, limitations. Start from docs/PHASE1_REPORT.md and docs/background_research.md.

See docs/ROADMAP.md P3.4."

echo "done"

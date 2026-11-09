# Next steps: from here to the mentor review and Phase III

Status as of `101fe46` on `main`. Owners are blank: assign a name to each row before work starts.
Order matters more than dates. Each step has a stop condition, so nothing downstream starts on a guess.

## Where things stand

| Area | State | Evidence |
|---|---|---|
| Phase I scanner, CBOM, tests, CI | Done | `results/RESULTS.md`, 110 tests pass |
| P2.1 dataset rebuilt with Espressif GCC | Done | `dataset/out_esp32`, 231 images |
| P2.2 held-out set (32 ESP-IDF images) | Done, frozen | `dataset/heldout`, `docs/HELDOUT.md` |
| P2.3 disassembly | Done for windowed ABI | `docs/DISASM.md` |
| P2.4 function starts | Done (dev images only) | `docs/FUNCTIONS.md` |
| P2.5 function labels (41,051) | Done | `dataset/functions/labels.jsonl.gz` |
| P2.6 features | Done | `cbomscan/mlfeatures.py` |
| P2.7 classifier | **Not done**: code exists, no trained model, no held-out score | `eval/phase2_ml.py` |
| P2.8 rules vs rules+ML on held-out | **Not done** | no `results/phase2/RESULTS_phase2.md` |
| P2.9 post-quantum rules | Done for ML-KEM and ML-DSA; LMS partial; SLH-DSA not started | `docs/PQC_RULES.md` |
| Board test (flash dump from a real ESP32) | **Not done**: no board attached | `scripts/board_test.py` |
| Dashboard (Cryptolens) | Done, shows PQC families | `cbomscan/dashboard/` |
| Git tags `phase1-demo`, `heldout-frozen-1` | Missing on GitHub (push refused, HTTP 403) | local clones only |
| Phase III | Not started | `docs/ROADMAP.md` |

## Stage 1: close Phase II (about one week)

Stop rule: no ML number leaves this stage unless `RESULTS_phase2.md` exists and was produced by the command in `docs/PHASE2_ML.md`.

1. **Preserve the frozen references.** Push tags `heldout-frozen-1` and `phase1-demo` from a clone that has them. Owner: whoever holds the tags.
2. **Choose k on development data only.** Run `python eval/phase2_ml.py --skip-heldout`. Accept the chosen k from cross-validation. Do not change it after the next step.
3. **Score the held-out set once.** Run `python eval/phase2_ml.py` (full run). This is the only held-out score for the ML. Commit `results/phase2/RESULTS_phase2.md` and the model file with its SHA-256 metadata.
4. **Report both results.** Rules alone, and rules plus ML, on the held-out set. Give the MD5 truth defect as both figures: as frozen (recall 0.821) and with those cells excluded (0.863).
   - *Stop condition:* if the ML does not improve recall on ECDH, Poly1305 or ECDSA, report that as the result. Do not tune again.
5. **Integration test.** Add the test from P2.8 that runs `cbomscan scan --ml` on one held-out image and checks the evidence group is `ml`.
6. **Board test, two routes.**
   - *With a board:* `python scripts/board_test.py --port COMx`, then record the output in `docs/BOARD_TEST.md`.
   - *Without a board:* rehearse on a synthetic dump (`dataset/make_flash_dump.py`) and label the result "not tested on hardware". Do not claim more.
7. **Close the docs.** Update `docs/ROADMAP.md` ticks, the README status table, and `docs/PHASE2_ML.md` (remove "work in progress" only after step 3).

Deliverable: a Phase II report with the table below, which has every number traced to a file.

| Metric (held-out) | Rules | Strings baseline | Rules + ML |
|---|---|---|---|
| Precision | 0.996 | 0.93 | to fill |
| Recall | 0.821 | 0.98 | to fill |
| ECDH recall | 0 of 32 | to fill | to fill |

## Stage 2: presentation (parallel with Stage 1)

1. **Dashboard shows ML evidence.** When a scan uses `--ml`, the evidence line reads "function classifier" and shows the development cross-validation precision, not a probability. Owner: dashboard.
2. **Mentor script.** Use `docs/` material and the console demo in the order from the earlier walkthrough. Show a sample scan, the threshold slider at 0.40, and the post-quantum example.
3. **Freeze the demo.** Build `docs/dashboard-demo.html` once and do not change it after the review starts.
4. **Rehearse twice**, once on the laptop and once offline, to check nothing depends on the network.

## Stage 3: Phase III (choose scope with the mentor)

Scope to what is credible in the remaining time. Items in order of value per effort:

1. **P3.1 migration feasibility** (highest value, no hardware needed). For each finding, check the replacement against the image's partition size and the chip's RAM. Use published sizes, for example ML-DSA-65: public key 1,952 bytes, signature 3,309 bytes. Show every assumption in the report.
2. **P3.2 more chips, scoped.** ESP32-S2 and S3 are Xtensa, so the existing disassembler may apply in part; test it on images before claiming support. ESP32-C3, C5 and C6 are **RISC-V**, which the current disassembler and function recovery cannot read. Those need a new instruction decoder. Say so explicitly; do not present them as a simple extension.
3. **P3.3 demo (optional).** Only if a C5 or C6 board is available and ESP-IDF 6.0 installs. Otherwise cut it and say why.
4. **P3.4 write-up.** Start from `docs/PHASE1_REPORT.md` and `docs/background_research.md`. Include the held-out results and the limitations in `docs/HELDOUT.md`.

## Blockers and what to do about them

| Blocker | Effect | Action |
|---|---|---|
| No ESP32 attached | Board test and P3.3 cannot run | Use the synthetic route; state it |
| GitHub refuses tag pushes from this environment | Tags stay local | Push from a laptop with write access |
| ESP-IDF install on laptops | Blocks rebuilds and P3.3 | One owner does all ESP-IDF work |
| Team time | Phase III may not fit | Stop after P3.1 and P3.4 if needed |

## Rules that stay fixed

- Tune only on development data. The held-out set is scored once per change.
- Report figures that are worse than the baseline, including the strings baseline beating the rules on recall.
- Quote no ML number until `RESULTS_phase2.md` exists.

# Phase II ML tier

Optional, off by default. Finds crypto the Tier 1 rules miss by classifying individual functions of a stripped
ESP32 image. **Status: trained and scored once on the frozen held-out set. It raises recall but does not meet the
precision goal, so it stays off by default.** Model: `models/function_classifier.joblib` with metadata and SHA-256 in
`models/function_classifier.json`.

## Pipeline

1. `cbomscan/functions.py` recovers function starts (aligned `entry a1`, sweep-filtered; docs/FUNCTIONS.md).
2. `cbomscan/mlfeatures.py` builds 911 features per function: instruction n-grams and shape (`ins`), and the 32-bit
   literals loaded with `l32r` (`const`).
3. `eval/phase2_ml.py` trains a gradient-boosted classifier (scikit-learn `HistGradientBoostingClassifier`) on the
   **development** functions (`dataset/functions/labels.jsonl.gz`, 41,051 functions, 165 images). Classes: the 13
   scored families + `support` + `other`.
4. A family is reported for an image when at least `k` recovered functions are classified as it. `k` is chosen by
   leave-one-optimisation-level-out cross-validation on development data only.
5. `cbomscan scan --ml` adds that as evidence (`cbomscan/ml.py`). Its confidence is the family's development CV
   precision (stored in `models/function_classifier.json`), not a guess.

## Train it on your own machine

```bash
pip install -r requirements-phase2.txt        # capstone 6 pre-release, scikit-learn, numpy
python eval/phase2_ml.py --skip-heldout       # development cross-validation only; writes results/phase2/dev_cv.json
python eval/phase2_ml.py                      # full run: also fits the final models, scores the held-out set,
                                              # writes models/function_classifier.{joblib,json} and RESULTS_phase2.md
python -m cbomscan scan firmware.bin --ml
```

Expect tens of minutes (about 5 minutes per cross-validation fold on a 12-core machine; features are cached in
`dataset/functions/cache/`). No ELF files are needed: labels and images are committed.

## Rules that keep the result honest

- The held-out set (`dataset/heldout`, tag `heldout-frozen-1`) is for scoring only. The full run scores it; every
  further run on a changed model or feature set makes the held-out result less clean for that change. Tune on
  development data (`--skip-heldout`), score the held-out set once, and say so if you did otherwise.
- Report as-frozen and post-hoc figures separately (see `results/heldout/ANALYSIS.md` on the MD5 truth defect).
- The model file is a joblib (pickle) artefact. `load_model` checks its SHA-256 against the metadata, but only load
  models you trained or trust.

## Held-out result (scored once, 2026-11-09)

Source: [results/phase2/RESULTS_phase2.md](../results/phase2/RESULTS_phase2.md). k = 2 was chosen on development
data before the held-out set was predicted. The shipped model is `ml:ins+const`, fixed before scoring;
`ml:ins` and `ml:const` are ablations and were not used to choose anything.

| System (32 held-out images) | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| strings baseline | 0.93 | 0.98 | 0.95 | 328 | 24 | 8 |
| rules | 1.00 | 0.82 | 0.90 | 276 | 1 | 60 |
| ML alone (`ml:ins+const`) | 0.85 | 0.79 | 0.82 | 265 | 48 | 71 |
| **rules + ML** (shipped) | 0.86 | 0.92 | 0.89 | 309 | 49 | 27 |

On the three gap families (rules vs rules + ML, true positives out of images that contain the family):

| Family | Rules | Rules + ML | False positives added by ML |
|---|---|---|---|
| ECDH | 0 / 32 | 13 / 32 | 0 |
| ECDSA | 24 / 32 | 25 / 32 | 0 |
| Poly1305 | 0 / 4 | 3 / 4 | 24 (of 28 images without Poly1305) |

**Verdict: the P2.8 acceptance criterion is not met.** Recall rises from 0.82 to 0.92 and ECDH is found for the
first time, but precision falls from 1.00 to 0.86 (goal: at least 0.95). Most new false positives are Poly1305 (24),
DES (16) and ChaCha20 (8). The strings baseline still has the best F1 on this set.

**Why the confidence misleads.** ML evidence carries the family's development cross-validation precision as its
confidence. Several families score 1.0 there (Poly1305, ChaCha20, ECDH) because the development set has one
library family; on wolfSSL and ESP-IDF builds those numbers are far too high.

**Decision.** The ML tier stays **off by default** (`--ml` to enable) and the dashboard labels its evidence as
"Function classifier". Any change chosen from these numbers (for example, accepting ML evidence only for ECDH)
would be tuned on the held-out set; it needs a new held-out set to be measured cleanly.

## Development cross-validation (this run)

Function accuracy by left-out optimisation level: -O0 0.555, -O1 0.832, -O2 0.901, -O3 0.893, -Os 0.778 (overall
0.776). Image-level micro F1 by k: 1: 0.877, 2: 0.892, 3: 0.820, 5: 0.645. Source:
[results/phase2/dev_cv.json](../results/phase2/dev_cv.json).

## Earlier facts (first run, 100 iterations)

Function accuracy by left-out optimisation level: -O0 0.56, -O1 0.84, -O2 0.91, -O3 0.89, -Os 0.78. Image-level
micro F1 at k=2: 0.885 on development, below the Phase I rules' 0.93 on the same set, so the classifier alone does not
beat the rules there; the open question is whether rules + ML improves recall on the held-out gaps (ECDH, Poly1305,
wolfSSL ECDSA). Source: `results/phase2/dev_cv_first_run_100iter.json`.

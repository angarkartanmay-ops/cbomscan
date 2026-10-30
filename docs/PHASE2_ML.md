# Phase II ML tier (work in progress)

Optional, off by default. Finds crypto the Tier 1 rules miss by classifying individual functions of a stripped
ESP32 image. **Status: code complete, model not yet trained or scored in this repository's committed results.**
Do not quote any ML number until `results/phase2/RESULTS_phase2.md` exists and was produced by the command below.

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

## Known facts so far (development cross-validation, first run; 100 iterations)

Function accuracy by left-out optimisation level: -O0 0.56, -O1 0.84, -O2 0.91, -O3 0.89, -Os 0.78. Image-level
micro F1 at k=2: 0.885 on development, below the Phase I rules' 0.93 on the same set, so the classifier alone does not
beat the rules there; the open question is whether rules + ML improves recall on the held-out gaps (ECDH, Poly1305,
wolfSSL ECDSA). Source: `results/phase2/dev_cv_first_run_100iter.json`.

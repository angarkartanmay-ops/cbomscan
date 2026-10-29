# Contributing

## Workflow

1. Pick an open issue (or open one) and assign yourself.
2. Branch from `main`: `git checkout -b p2.4-function-boundaries`.
3. Make the change with tests.
4. Run locally:
   ```bash
   python -m pytest -q tests
   python eval/evaluate.py      # if you touched detection
   ```
5. Open a pull request that says what changed, why, and how the metrics moved (paste the
   "Systems compared" table if detection changed). Link the issue (`Closes #12`).
6. Another teammate reviews before merge. CI must be green.

## Rules of the road

- **Never tune on the held-out set.** Rules and models are developed on `dataset/out`; the
  held-out set (Phase II) is only for final numbers.
- **Report what the evaluation shows**, including regressions and failures. Gaps are results.
- **Prefer spec-derived constants** to values copied from one library.
- **Keep the CBOM schema-valid.** `validate.py` runs on every scan; tests check it too.
- **Do not commit** `third_party/`, ELF/map files, `_obj/`, or keys (see `.gitignore`).
- Commit messages: imperative, short subject (`Add ML-KEM zeta table rule`).

## Labels

| Label | Meaning |
|---|---|
| `phase-2`, `phase-3` | Which EL phase the work belongs to |
| `dataset`, `detection`, `ml`, `cbom`, `docs` | Area |
| `good first issue` | Small, self-contained |

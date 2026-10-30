# Function boundary recovery (P2.4)

`cbomscan/functions.py` recovers function starts in stripped ESP32 images (windowed ABI). It is rule based,
not learned, and uses only the development images.

## Rule

1. Candidates: 4-byte-aligned `entry a1, imm12` (`36 x1 yy`). All 41 589 true starts in the development
   images begin this way (checked from the ELF symbol tables), and all are 4-aligned.
2. Filter: swept with the Xtensa length rule from the previous kept start, a candidate that falls *inside* an
   instruction is dropped, unless the code right before it ends in `retw`/`retw.n` (+ up to 3 zero padding
   bytes). Without the exception a literal pool desynchronises the sweep and recall falls to 0.49
   (measured, see below). A function ends at the next start; the end is an upper bound.

## Measured (re-run: `python eval/eval_functions.py`)

Truth: STT_FUNC symbols (size > 0) of the unstripped ELF inside the code segments. 165 development images
(`dataset/out_esp32`, signed duplicates excluded).

| variant | precision | recall |
|---|---|---|
| aligned `entry a1` only | 0.995 | 1.000 |
| + length sweep, no return exception | 1.000 | 0.489 |
| + length sweep with return exception (shipped) | 1.000 | 0.987 |

Per level (shipped): recall 0.997 (-O0), 0.980 (-O1), 0.983 (-O2), 0.981 (-O3), 0.991 (-Os);
details in `results/functions/RESULTS_functions.md`. The 0.995 precision of the plain rule came entirely from
30 sampled starts inside function bodies (checked: every one was covered by a larger function symbol).

## Limits

- **In-distribution.** The rule was chosen on these images (our own link scripts, GCC 16.1, mbedTLS). Its
  behaviour on ESP-IDF and wolfSSL builds is measured once on the frozen held-out set and not tuned
  afterwards (`results/heldout/`).
- Functions that do not start with `entry a1` (hand-written assembly, call0-ABI images like the Phase I set)
  are not found. Phase I images were not evaluated.
- No function symbol sizes: ends are upper bounds that include trailing literals and padding.

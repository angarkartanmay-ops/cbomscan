# Phase II results: function classifier and ablation (frozen held-out set)

Command: `python eval/phase2_ml.py`. Models trained on the development set only (41051 functions, 165 images); k = 2 (min. functions per family), chosen by leave-one-optimisation-level-out CV on development data. Held-out: 32 images, tag `heldout-frozen-1`, predicted once. wolfSSL is a library no training image contains.

## Systems (micro-average over the 13 families; image-level presence)

| System | all 32 | mbedTLS (16) | wolfSSL (16) | -O0 | -Og | -O2 | -Os |
|---|---|---|---|---|---|---|---|
| strings-baseline | P 0.93 R 0.98 F1 0.95 | P 0.91 R 1.00 F1 0.95 | P 0.95 R 0.95 F1 0.95 | P 0.93 R 0.98 F1 0.95 | P 0.93 R 0.98 F1 0.95 | P 0.93 R 0.98 F1 0.95 | P 0.93 R 0.98 F1 0.95 |
| rules:constants | P 1.00 R 0.65 F1 0.79 | P 1.00 R 0.60 F1 0.75 | P 0.99 R 0.70 F1 0.82 | P 1.00 R 0.65 F1 0.79 | P 1.00 R 0.65 F1 0.79 | P 1.00 R 0.65 F1 0.79 | P 0.98 R 0.65 F1 0.79 |
| rules:all | P 1.00 R 0.82 F1 0.90 | P 1.00 R 0.80 F1 0.89 | P 0.99 R 0.84 F1 0.91 | P 1.00 R 0.82 F1 0.90 | P 1.00 R 0.82 F1 0.90 | P 1.00 R 0.82 F1 0.90 | P 0.99 R 0.82 F1 0.90 |
| ml:ins | P 0.81 R 0.86 F1 0.83 | P 0.75 R 0.92 F1 0.83 | P 0.88 R 0.81 F1 0.84 | P 0.80 R 0.81 F1 0.80 | P 0.81 R 0.87 F1 0.84 | P 0.82 R 0.93 F1 0.87 | P 0.80 R 0.83 F1 0.82 |
| ml:const | P 0.88 R 0.86 F1 0.87 | P 0.83 R 0.90 F1 0.86 | P 0.92 R 0.82 F1 0.87 | P 0.84 R 0.88 F1 0.86 | P 0.86 R 0.89 F1 0.88 | P 0.87 R 0.87 F1 0.87 | P 0.94 R 0.80 F1 0.86 |
| ml:ins+const | P 0.85 R 0.79 F1 0.82 | P 0.78 R 0.78 F1 0.78 | P 0.92 R 0.80 F1 0.86 | P 0.86 R 0.80 F1 0.83 | P 0.80 R 0.79 F1 0.79 | P 0.88 R 0.86 F1 0.87 | P 0.86 R 0.71 F1 0.78 |
| rules:all + ml:ins+const | P 0.86 R 0.92 F1 0.89 | P 0.81 R 0.96 F1 0.88 | P 0.92 R 0.89 F1 0.90 | P 0.88 R 0.93 F1 0.90 | P 0.82 R 0.89 F1 0.85 | P 0.89 R 0.95 F1 0.92 | P 0.87 R 0.90 F1 0.89 |
| rules:all + ml:ins | P 0.82 R 0.95 F1 0.88 | P 0.76 R 0.97 F1 0.86 | P 0.89 R 0.93 F1 0.91 | P 0.81 R 0.88 F1 0.85 | P 0.83 R 0.98 F1 0.90 | P 0.83 R 0.96 F1 0.89 | P 0.83 R 0.98 F1 0.90 |
| rules:all + ml:const | P 0.88 R 0.91 F1 0.89 | P 0.84 R 0.94 F1 0.89 | P 0.92 R 0.88 F1 0.90 | P 0.84 R 0.88 F1 0.86 | P 0.87 R 0.92 F1 0.89 | P 0.88 R 0.92 F1 0.90 | P 0.94 R 0.92 F1 0.93 |

Counts (all 32, as frozen): strings-baseline: TP 328 FP 24 FN 8; rules:constants: TP 220 FP 1 FN 116; rules:all: TP 276 FP 1 FN 60; ml:ins: TP 289 FP 68 FN 47; ml:const: TP 289 FP 41 FN 47; ml:ins+const: TP 265 FP 48 FN 71; rules:all + ml:ins+const: TP 309 FP 49 FN 27; rules:all + ml:ins: TP 319 FP 68 FN 17; rules:all + ml:const: TP 305 FP 42 FN 31

Post-hoc (MD5 cells of the 16 mbedTLS images excluded because the frozen truth overstates them, see `results/heldout/ANALYSIS.md`): strings-baseline: P 0.929 R 0.975 F1 0.951; rules:constants: P 0.995 R 0.688 F1 0.813; rules:all: P 0.996 R 0.863 F1 0.925; ml:ins: P 0.801 R 0.853 F1 0.826; ml:const: P 0.872 R 0.872 F1 0.872; ml:ins+const: P 0.838 R 0.778 F1 0.807; rules:all + ml:ins+const: P 0.857 R 0.916 F1 0.885; rules:all + ml:ins: P 0.817 R 0.947 F1 0.877; rules:all + ml:const: P 0.875 R 0.922 F1 0.898

## Per family, all 32 images (TP / FP / FN)

| Family | n true | strings-baseline | rules:constants | rules:all | ml:ins | ml:const | ml:ins+const | rules:all + ml:ins+const | rules:all + ml:ins | rules:all + ml:const |
|---|---|---|---|---|---|---|---|---|---|---|
| AES | 32 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 30/0/2 | 32/0/0 | 32/0/0 | 32/0/0 |
| DES | 16 | 16/16/0 | 16/0/0 | 16/0/0 | 13/16/3 | 15/15/1 | 15/16/1 | 16/16/0 | 16/16/0 | 16/15/0 |
| CHACHA20 | 0 | 0/4/0 | 0/1/0 | 0/1/0 | 0/26/0 | 0/3/0 | 0/7/0 | 0/8/0 | 0/26/0 | 0/4/0 |
| POLY1305 | 4 | 4/0/0 | 0/0/4 | 0/0/4 | 3/24/1 | 3/22/1 | 3/24/1 | 3/24/1 | 3/24/1 | 3/22/1 |
| MD5 | 32 | 32/0/0 | 16/0/16 | 16/0/16 | 24/0/8 | 25/0/7 | 31/0/1 | 32/0/0 | 32/0/0 | 26/0/6 |
| SHA1 | 32 | 24/0/8 | 32/0/0 | 32/0/0 | 31/0/1 | 29/0/3 | 20/0/12 | 32/0/0 | 32/0/0 | 32/0/0 |
| SHA256 | 32 | 32/0/0 | 32/0/0 | 32/0/0 | 30/0/2 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 |
| SHA512 | 32 | 32/0/0 | 32/0/0 | 32/0/0 | 29/0/3 | 32/0/0 | 31/0/1 | 32/0/0 | 32/0/0 | 32/0/0 |
| RSA | 32 | 32/0/0 | 0/0/32 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 |
| ECDSA | 32 | 32/0/0 | 0/0/32 | 24/0/8 | 14/0/18 | 24/0/8 | 21/0/11 | 25/0/7 | 24/0/8 | 26/0/6 |
| ECDH | 32 | 32/0/0 | 0/0/32 | 0/0/32 | 24/0/8 | 14/0/18 | 13/0/19 | 13/0/19 | 24/0/8 | 14/0/18 |
| ECC | 32 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 | 32/0/0 |
| FFDH | 28 | 28/4/0 | 28/0/0 | 28/0/0 | 25/2/3 | 19/1/9 | 5/1/23 | 28/1/0 | 28/2/0 | 28/1/0 |

## Development cross-validation (leave one optimisation level out; ins+const)

Function-level accuracy 0.776. Image-level micro F1 by k: k=1: 0.877, k=2: 0.892, k=3: 0.820, k=5: 0.645, k=8: 0.483, k=12: 0.357, k=20: 0.219. Chosen k = 2.

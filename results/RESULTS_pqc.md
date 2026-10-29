# Post-quantum rule evaluation (P2.9)

Positives: 45 images from real reference implementations built with Espressif xtensa-esp32-elf-gcc (windowed ABI). Negatives: 198 Phase I images (no post-quantum code).

In-distribution: rules were derived from FIPS 203/204 and verified on these same builds.

| Family | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| MLKEM | 10 | 0 | 0 | 1.00 | 1.00 |
| MLDSA | 10 | 0 | 0 | 1.00 | 1.00 |
| LMS | 20 | 0 | 5 | 1.00 | 0.80 |

## Recall by implementation and optimisation level (positives only)

| Implementation | O0 | O1 | O2 | O3 | Os |
|---|---|---|---|---|---|
| hashsigs_h10_w4 | found | found | found | found | found |
| hashsigs_h5_w1 | found | found | found | found | found |
| hashsigs_h5_w2 | found | found | found | found | found |
| hashsigs_h5_w8 | found | found | found | found | found |
| hashsigs_nokey | MISSED | MISSED | MISSED | MISSED | MISSED |
| mldsa_native65 | found | found | found | found | found |
| mlkem_native768 | found | found | found | found | found |
| pqclean_mldsa65 | found | found | found | found | found |
| pqclean_mlkem768 | found | found | found | found | found |

# Phase I evaluation results

Dataset: 32 unsigned firmware images (2 library variants x 4 optimisation levels x 8 profiles) plus 0 Secure Boot V2 signed copies. Truth is the set of algorithm families whose code is linked into each image, taken from the linker map. Scores are image-level family detection, micro-averaged over 13 families unless stated.

## Systems compared

| System | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| strings-baseline | 0.93 | 0.98 | 0.95 | 328 | 24 | 8 |
| rules:constants | 1.00 | 0.65 | 0.79 | 220 | 1 | 116 |
| rules:constants+oid | 1.00 | 0.75 | 0.86 | 252 | 1 | 84 |
| rules:constants+oid+keys | 1.00 | 0.75 | 0.86 | 252 | 1 | 84 |
| rules:no-names | 1.00 | 0.75 | 0.86 | 252 | 1 | 84 |
| rules:all | 1.00 | 0.82 | 0.90 | 276 | 1 | 60 |

## Per family (rules:all)

| Family | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| AES | 1.00 | 1.00 | 1.00 | 32 | 0 | 0 | 0 |
| DES | 1.00 | 1.00 | 1.00 | 16 | 0 | 0 | 16 |
| CHACHA20 | 0.00 | 0.00 | 0.00 | 0 | 1 | 0 | 31 |
| POLY1305 | 0.00 | 0.00 | 0.00 | 0 | 0 | 4 | 28 |
| MD5 | 1.00 | 0.50 | 0.67 | 16 | 0 | 16 | 0 |
| SHA1 | 1.00 | 1.00 | 1.00 | 32 | 0 | 0 | 0 |
| SHA256 | 1.00 | 1.00 | 1.00 | 32 | 0 | 0 | 0 |
| SHA512 | 1.00 | 1.00 | 1.00 | 32 | 0 | 0 | 0 |
| RSA | 1.00 | 1.00 | 1.00 | 32 | 0 | 0 | 0 |
| ECDSA | 1.00 | 0.75 | 0.86 | 24 | 0 | 8 | 0 |
| ECDH | 0.00 | 0.00 | 0.00 | 0 | 0 | 32 | 0 |
| ECC | 1.00 | 1.00 | 1.00 | 32 | 0 | 0 | 0 |
| FFDH | 1.00 | 1.00 | 1.00 | 28 | 0 | 0 | 4 |

## Per family: strings baseline vs rules (F1)

| Family | strings-baseline | rules:all |
|---|---|---|
| AES | 1.00 | 1.00 |
| DES | 0.67 | 1.00 |
| CHACHA20 | 0.00 | 0.00 |
| POLY1305 | 1.00 | 0.00 |
| MD5 | 1.00 | 0.67 |
| SHA1 | 0.86 | 1.00 |
| SHA256 | 1.00 | 1.00 |
| SHA512 | 1.00 | 1.00 |
| RSA | 1.00 | 1.00 |
| ECDSA | 1.00 | 0.86 |
| ECDH | 1.00 | 0.00 |
| ECC | 1.00 | 1.00 |
| FFDH | 0.93 | 1.00 |

## By optimisation level (rules:all)

| Opt | Precision | Recall | F1 |
|---|---|---|---|
| O0 | 1.00 | 0.82 | 0.90 |
| O2 | 1.00 | 0.82 | 0.90 |
| Og | 1.00 | 0.82 | 0.90 |
| Os | 0.99 | 0.82 | 0.90 |

## By library variant (rules:all)

| Variant | Precision | Recall | F1 |
|---|---|---|---|
| esp-idf-v5.5.6 | 1.00 | 0.80 | 0.89 |
| wolfssl-v5.9.4-on-esp-idf-v5.5.6 | 0.99 | 0.84 | 0.91 |

## Quantum-vulnerable public-key classes

| Class | strings P/R | rules:all P/R |
|---|---|---|
| RSA | 1.00 / 1.00 | 1.00 / 1.00 |
| ECC | 1.00 / 1.00 | 1.00 / 1.00 |
| FFDH | 0.88 / 1.00 | 1.00 / 1.00 |

Image-level 'contains quantum-vulnerable public-key crypto': rules P=1.00 R=1.00 (TP 32, FP 0, FN 0, TN 0); strings baseline P=1.00 R=1.00.

## Secure Boot V2 signature blocks

0/0 signed images: scheme, key size and curve recovered correctly from the signature block.

## Where evidence addresses fall (rules:all)

| Rule group | Location | Evidence items |
|---|---|---|
| constants | same-family object | 442 |
| constants | application / other | 67 |
| constants | other crypto object | 12 |
| oid | application / other | 136 |
| strings | application / other | 66 |
| names | application / other | 219 |
| keys | application / other | 1432 |
| hw | application / other | 64 |

Scan time per image: mean 439 ms, max 889 ms (pure Python).

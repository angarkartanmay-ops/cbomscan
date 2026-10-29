# Phase I evaluation results

Dataset: 165 unsigned firmware images (3 library variants x 5 optimisation levels x 11 profiles) plus 66 Secure Boot V2 signed copies. Truth is the set of algorithm families whose code is linked into each image, taken from the linker map. Scores are image-level family detection, micro-averaged over 13 families unless stated.

## Systems compared

| System | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| strings-baseline | 0.86 | 0.80 | 0.83 | 948 | 150 | 242 |
| rules:constants | 1.00 | 0.72 | 0.84 | 858 | 0 | 332 |
| rules:constants+oid | 1.00 | 0.78 | 0.88 | 930 | 0 | 260 |
| rules:constants+oid+keys | 1.00 | 0.78 | 0.88 | 930 | 0 | 260 |
| rules:no-names | 1.00 | 0.80 | 0.89 | 950 | 0 | 240 |
| rules:all | 1.00 | 0.86 | 0.93 | 1028 | 0 | 162 |

## Per family (rules:all)

| Family | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| AES | 1.00 | 0.46 | 0.63 | 65 | 0 | 75 | 25 |
| DES | 1.00 | 1.00 | 1.00 | 90 | 0 | 0 | 75 |
| CHACHA20 | 1.00 | 1.00 | 1.00 | 45 | 0 | 0 | 120 |
| POLY1305 | 1.00 | 0.07 | 0.12 | 3 | 0 | 42 | 120 |
| MD5 | 1.00 | 1.00 | 1.00 | 135 | 0 | 0 | 30 |
| SHA1 | 1.00 | 1.00 | 1.00 | 135 | 0 | 0 | 30 |
| SHA256 | 1.00 | 1.00 | 1.00 | 135 | 0 | 0 | 30 |
| SHA512 | 1.00 | 1.00 | 1.00 | 150 | 0 | 0 | 15 |
| RSA | 1.00 | 1.00 | 1.00 | 90 | 0 | 0 | 75 |
| ECDSA | 1.00 | 1.00 | 1.00 | 60 | 0 | 0 | 105 |
| ECDH | 0.00 | 0.00 | 0.00 | 0 | 0 | 45 | 120 |
| ECC | 1.00 | 1.00 | 1.00 | 90 | 0 | 0 | 75 |
| FFDH | 1.00 | 1.00 | 1.00 | 30 | 0 | 0 | 135 |

## Per family: strings baseline vs rules (F1)

| Family | strings-baseline | rules:all |
|---|---|---|
| AES | 0.84 | 0.63 |
| DES | 0.92 | 1.00 |
| CHACHA20 | 1.00 | 1.00 |
| POLY1305 | 0.80 | 0.12 |
| MD5 | 0.80 | 1.00 |
| SHA1 | 0.88 | 1.00 |
| SHA256 | 0.88 | 1.00 |
| SHA512 | 0.82 | 1.00 |
| RSA | 1.00 | 1.00 |
| ECDSA | 0.80 | 1.00 |
| ECDH | 0.55 | 0.00 |
| ECC | 0.77 | 1.00 |
| FFDH | 0.33 | 1.00 |

## By optimisation level (rules:all)

| Opt | Precision | Recall | F1 |
|---|---|---|---|
| O0 | 1.00 | 0.87 | 0.93 |
| O1 | 1.00 | 0.86 | 0.93 |
| O2 | 1.00 | 0.86 | 0.93 |
| O3 | 1.00 | 0.86 | 0.93 |
| Os | 1.00 | 0.86 | 0.93 |

## By library variant (rules:all)

| Variant | Precision | Recall | F1 |
|---|---|---|---|
| m228 | 1.00 | 0.83 | 0.91 |
| m36 | 1.00 | 0.84 | 0.91 |
| m36rom | 1.00 | 0.93 | 0.96 |

## Quantum-vulnerable public-key classes

| Class | strings P/R | rules:all P/R |
|---|---|---|
| RSA | 1.00 / 1.00 | 1.00 / 1.00 |
| ECC | 0.75 / 1.00 | 1.00 / 1.00 |
| FFDH | 1.00 / 0.20 | 1.00 / 1.00 |

Image-level 'contains quantum-vulnerable public-key crypto': rules P=1.00 R=1.00 (TP 135, FP 0, FN 0, TN 30); strings baseline P=1.00 R=0.91.

## Secure Boot V2 signature blocks

66/66 signed images: scheme, key size and curve recovered correctly from the signature block.

## Where evidence addresses fall (rules:all)

| Rule group | Location | Evidence items |
|---|---|---|
| constants | same-family object | 1797 |
| constants | application / other | 30 |
| constants | other crypto object | 15 |
| oid | crypto support object (OID/PK/MD tables) | 342 |
| names | crypto support object (OID/PK/MD tables) | 765 |
| strings | crypto support object (OID/PK/MD tables) | 84 |
| strings | same-family object | 6 |
| keys | application / other | 90 |
| hw | same-family object | 60 |

Scan time per image: mean 92 ms, max 302 ms (pure Python).

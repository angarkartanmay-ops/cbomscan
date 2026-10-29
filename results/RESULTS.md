# Phase I evaluation results

Dataset: 132 unsigned firmware images (3 library variants x 4 optimisation levels x 11 profiles) plus 66 Secure Boot V2 signed copies. Truth is the set of algorithm families whose code is linked into each image, taken from the linker map. Scores are image-level family detection, micro-averaged over 13 families unless stated.

## Systems compared

| System | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| strings-baseline | 0.86 | 0.80 | 0.83 | 760 | 125 | 192 |
| rules:constants | 1.00 | 0.72 | 0.84 | 687 | 0 | 265 |
| rules:constants+oid | 1.00 | 0.78 | 0.88 | 747 | 0 | 205 |
| rules:constants+oid+keys | 1.00 | 0.78 | 0.88 | 747 | 0 | 205 |
| rules:no-names | 1.00 | 0.80 | 0.89 | 763 | 0 | 189 |
| rules:all | 1.00 | 0.86 | 0.93 | 823 | 0 | 129 |

## Per family (rules:all)

| Family | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| AES | 1.00 | 0.46 | 0.63 | 52 | 0 | 60 | 20 |
| DES | 1.00 | 1.00 | 1.00 | 72 | 0 | 0 | 60 |
| CHACHA20 | 1.00 | 1.00 | 1.00 | 36 | 0 | 0 | 96 |
| POLY1305 | 1.00 | 0.08 | 0.15 | 3 | 0 | 33 | 96 |
| MD5 | 1.00 | 1.00 | 1.00 | 108 | 0 | 0 | 24 |
| SHA1 | 1.00 | 1.00 | 1.00 | 108 | 0 | 0 | 24 |
| SHA256 | 1.00 | 1.00 | 1.00 | 108 | 0 | 0 | 24 |
| SHA512 | 1.00 | 1.00 | 1.00 | 120 | 0 | 0 | 12 |
| RSA | 1.00 | 1.00 | 1.00 | 72 | 0 | 0 | 60 |
| ECDSA | 1.00 | 1.00 | 1.00 | 48 | 0 | 0 | 84 |
| ECDH | 0.00 | 0.00 | 0.00 | 0 | 0 | 36 | 96 |
| ECC | 1.00 | 1.00 | 1.00 | 72 | 0 | 0 | 60 |
| FFDH | 1.00 | 1.00 | 1.00 | 24 | 0 | 0 | 108 |

## Per family: strings baseline vs rules (F1)

| Family | strings-baseline | rules:all |
|---|---|---|
| AES | 0.85 | 0.63 |
| DES | 0.92 | 1.00 |
| CHACHA20 | 1.00 | 1.00 |
| POLY1305 | 0.80 | 0.15 |
| MD5 | 0.80 | 1.00 |
| SHA1 | 0.88 | 1.00 |
| SHA256 | 0.88 | 1.00 |
| SHA512 | 0.82 | 1.00 |
| RSA | 1.00 | 1.00 |
| ECDSA | 0.80 | 1.00 |
| ECDH | 0.55 | 0.00 |
| ECC | 0.77 | 1.00 |
| FFDH | 0.34 | 1.00 |

## By optimisation level (rules:all)

| Opt | Precision | Recall | F1 |
|---|---|---|---|
| O0 | 1.00 | 0.87 | 0.93 |
| O1 | 1.00 | 0.86 | 0.93 |
| O2 | 1.00 | 0.86 | 0.93 |
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
| FFDH | 0.55 / 0.25 | 1.00 / 1.00 |

Image-level 'contains quantum-vulnerable public-key crypto': rules P=1.00 R=1.00 (TP 108, FP 0, FN 0, TN 24); strings baseline P=1.00 R=0.92.

## Secure Boot V2 signature blocks

66/66 signed images: scheme, key size and curve recovered correctly from the signature block.

## Where evidence addresses fall (rules:all)

| Rule group | Location | Evidence items |
|---|---|---|
| constants | same-family object | 1439 |
| constants | application / other | 24 |
| constants | other crypto object | 12 |
| oid | crypto support object (OID/PK/MD tables) | 276 |
| names | crypto support object (OID/PK/MD tables) | 600 |
| strings | crypto support object (OID/PK/MD tables) | 72 |
| strings | same-family object | 6 |
| keys | application / other | 72 |
| hw | same-family object | 48 |

Scan time per image: mean 44 ms, max 178 ms (pure Python).

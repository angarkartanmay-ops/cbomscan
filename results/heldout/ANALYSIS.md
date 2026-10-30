# Held-out baseline: Phase I rules on the frozen set

Set: `dataset/heldout` (32 ESP-IDF v5.5.6 images, tag `heldout-frozen-1`, commit bc77dc9). Produced by
`python eval/evaluate.py --dataset dataset/heldout --out results/heldout` with the unchanged Phase I rules,
before any Phase II feature or model code existed. Figures below are copied from `RESULTS.md` / `per_sample.json`.

## Headline (micro-average over 13 families)

| System | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| rules:all | 0.996 | 0.821 | 0.900 | 276 | 1 | 60 |
| strings baseline | 0.93 | 0.98 | 0.95 | 328 | 24 | 8 |

Phase I development set (for comparison, same rules): P 1.00 / R 0.86 / F1 0.93. Precision holds on a different
compiler, build system and library; recall drops. **The strings baseline has higher recall and F1 than the
rules on this set.** Both ESP-IDF mbedTLS and wolfSSL ship family names in strings, which a name search finds;
that says little about stripped or vendor-built firmware with no such strings (the strings baseline's weakness
in Phase I). This is a limit of the test set, not a rule win for either system.

## Where the rules miss (60 FN, 1 FP): the targets for the ML tier

| Family | Missed | Where | Note |
|---|---|---|---|
| ECDH | 32 of 32 | every image | no constant specific to ECDH (shares curve constants with ECC); rules detect ECC, not ECDH |
| MD5 | 16 of 32 | all 16 mbedTLS images | **truth defect, see below** |
| ECDSA | 8 of 32 | `wolfssl_test`, `wolfssl_benchmark` | wolfSSL ECDSA not matched by the rules in these two apps |
| POLY1305 | 4 of 4 | `wolfssl_test` | wolfSSL Poly1305 not matched |
| CHACHA20 | 1 FP | `wolfssl_client` at -Os | false positive (the only one); not investigated |

Misses are the same at every optimisation level (recall 0.82 at -O0, -Og, -O2, -Os), so on this set the
misses come from library and family, not from optimisation level.

## Truth defect found after scoring (MD5 in the mbedTLS images): not corrected

The frozen truth marks MD5 present in the 16 mbedTLS images because a 97-byte `md5.c` object is linked.
`python eval/heldout_md5_note.py` shows the MD5 round constant `K[0] = 0xd76aa478` is in 0 of those 16 images and
in 16 of 16 wolfSSL images: the MD5 transform is not in the mbedTLS images (the 97 bytes are a wrapper; where MD5
actually runs, e.g. ROM, was not verified here). So those 16 MD5 "misses" are the truth overstating, not the rules failing.

The frozen files are **not edited** (that would contaminate the set). A secondary, post-hoc figure excludes those
16 cells: rules:all P 0.996 / R 0.863 / F1 0.925 (TP 276, FP 1, FN 44). Use the as-frozen figures as the
baseline and this one as a caveat. The same linked-object truth rule may overstate other families; not audited.

## Limits of this set

- No ChaCha20 in any image (recall unmeasurable); Poly1305 in 4 images only; DES in 16; FFDH in 28.
- The 16 mbedTLS images share one truth set, so they test detection under a different compiler/build, not
  family presence.
- Truth is linked capability from the map, not runtime use.

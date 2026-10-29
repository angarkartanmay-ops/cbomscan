# Post-quantum detection rules (P2.9)

Migrated firmware must show up correctly in the CBOM: ML-KEM, ML-DSA and LMS are reported as
**post-quantum, not vulnerable** (`cbomscan:quantumVulnerable=false`, `cbomscan:postQuantum=true`,
migration priority 6 = no action). They are not part of `SCORED_FAMILIES`, so the 13-family Phase I
metrics are unchanged (`python eval/evaluate.py` reproduces them; checked after this change).

## What is detected, and how the constants were derived

| Family | Rule | Constant | Derivation |
|---|---|---|---|
| ML-KEM (FIPS 203) | `mlkem.zetas_mont` | first 16 NTT zetas, int16 LE, signed Montgomery form | `zeta_i = 17^BitRev7(i) mod 3329` (Appendix A), times `2^16 mod q`, centred on 0 |
| ML-DSA (FIPS 204) | `mldsa.zetas_mont` | zetas 1..16, int32 LE, signed Montgomery form | `zeta_i = 1753^BitRev8(i) mod 8380417` (Appendix B), times `2^32 mod q`, centred on 0 |

| LMS / HSS (RFC 8554, SP 800-208) | `lms.pubkey` | embedded public key *structure*: BE u32 LMS type 5..9, BE u32 LM-OTS type 1..4, then 48 bytes with at least 36 distinct values | type codes from RFC 8554 section 5.1 / 4.1 |

Both tables are computed in `cbomscan/signatures.py` from the definitions, not pasted. The 32 / 64
matched bytes are high-entropy values fixed by the mathematics, so a chance match is negligible.

## What was verified against real bytes

`dataset/build_pqc.py` builds four independent reference implementations with Espressif's
`xtensa-esp32-elf-gcc` (windowed ABI, GCC 16.1.0, crosstool-NG `esp-16.1.0_20260609`), each at
`-O0 -O1 -O2 -Os -O3` (20 images, `dataset/out_pqc/`):

| Implementation | Revision | Family |
|---|---|---|
| PQClean `ml-kem-768/clean` | `0586a824fc0d` | ML-KEM |
| PQClean `ml-dsa-65/clean` | `0586a824fc0d` | ML-DSA |
| Cisco hash-sigs (LMS verify) | `a98815e338d3` | LMS (+ mbedTLS 3.6.7 `068ff080b369` for SHA-256) |
| mlkem-native (ML-KEM-768, C backend) | `08e1f3881ec1` | ML-KEM |
| mldsa-native (ML-DSA-65, C backend) | `f89fc5779656` | ML-DSA |

For every image, `truth.json` records the address and size of the zeta table (symbol found in the
unstripped ELF), and `tests/test_pqc.py::test_derived_table_equals_bytes_of_real_build` compares the
spec-derived table with the bytes at that address in the shipped `firmware.bin`:

- ML-KEM: all 128 entries equal the derived Montgomery table, in all 10 images.
- ML-DSA: entries 1..255 equal the derived table, in all 10 images. Entry 0 is an unused `0` in the
  reference code (the derived value would be `1 * 2^32 mod q`); the rule skips it.

## LMS: what was verified, and the blind spot

- **Type codes** (`test_lms_type_codes_match_hash_sigs_source`): the RFC 8554 codes in `signatures.py`
  (LMS 5..9, LM-OTS 1..4) are compared with the `#define`s in Cisco hash-sigs `common_defs.h`
  (revision `a98815e338d3`); they are equal. This is a source-level check against a reference
  implementation, as the codes are not tables in the binary.
- **Binary check:** 25 images link the real hash-sigs verifier (verify-only, SHA-256 from mbedTLS via
  hash-sigs' `EXT_SHA256_H` hook). In 20 of them a public key is embedded (4 parameter sets x 5
  optimisation levels); the scanner finds all 20 and decodes the right LMS and LM-OTS type
  (`test_lms_embedded_key_found_and_structure_matches_rfc8554`).
- **The embedded keys are ours, not from a reference generator.** Running hash-sigs' key generator
  natively on the build machine was not permitted, so `dataset/gen_lms_keys.py` implements RFC 8554
  key generation itself (deterministic throwaway seeds, so the "private" keys are public). Those keys
  were not cross-checked against a reference verifier here. They serve as realistic public-key
  *structures*; the claim made is "the structure detector finds RFC 8554 type codes followed by
  hash-like bytes in a real image", not "these are valid LMS keys".
- **Known miss, pinned by a test:** 5 images link the same verifier but read the key from flash at
  run time (nothing embedded). **The rules miss all 5** (LMS recall 20/25 = 0.80). LMS verification
  code has no constant a constant rule can see: its domain-separation values (`D_PBLC` 0x8080,
  `D_MESG` 0x8181, `D_LEAF` 0x8282, `D_INTR` 0x8383) are emitted as byte immediates
  (e.g. `movi a9, -128` then byte stores), and none of them appears as a word in the image. Detecting
  this needs instruction-level analysis (Phase II tier 2), so no weaker rule was added to paper over it.
- Other formats are not covered: a bare LMS public key without the HSS level count is matched (the
  level count is optional), but keys stored in other encodings (e.g. inside a certificate or wrapped
  in a vendor container), XMSS (RFC 8391), and signatures embedded without the key are not detected.

## Results

`python eval/evaluate_pqc.py` writes [`results/RESULTS_pqc.md`](../results/RESULTS_pqc.md). On 45 positive
images (20 ML-KEM/ML-DSA, 25 LMS) and the 198 Phase I images as negatives: ML-KEM 10/10, ML-DSA 10/10, LMS 20/25 (the 5 misses
are the run-time-key images above), no false positives
(and no post-quantum evidence of any strength on any Phase I image,
`test_no_pqc_evidence_on_any_phase1_image`).

**This is an in-distribution result.** The rules were derived from the standards and then checked
on these same builds. It says the constants match two different code bases at five optimisation
levels. It does not say anything about other implementations.

## Limits (do not over-claim)

- **Only the signed-Montgomery table form is matched.** It is what all four implementations store.
  The plain FIPS-appendix form is derivable but no build we have stores it, so no rule exists for
  it. Implementations that store the table in another form (int32 for ML-KEM, reordered for SIMD,
  computed at run time) would be missed. Not measured.
- **Parameter set not recovered.** The NTT table is identical for ML-KEM-512/768/1024 and for
  ML-DSA-44/65/87, and for the pre-standard Kyber and Dilithium. The CBOM therefore reports the
  lowest NIST level of the algorithm (1 for ML-KEM, 2 for ML-DSA) as a lower bound and says so in
  `cbomscan:note`. Kyber (draft) versus ML-KEM (FIPS 203) cannot be separated by this table.
- **SLH-DSA (FIPS 205) is not detected.** It has no large constant table; its parameters are small
  integers. This needs instruction-level work (Phase II tier 2), not constant rules.
- **Images built here are not boot-tested** (they follow the Phase I convention: valid ESP32 app
  images for static analysis; `randombytes` is a non-secure stub).

## Rebuilding the post-quantum images

Toolchain used: crosstool-NG `esp-16.1.0_20260609`, file
`xtensa-esp-elf-16.1.0_20260609-x86_64-w64-mingw32.zip` (247 075 663 bytes, SHA-256
`cb59cbfe7f8ce35700dc407e4ce17af95576cc11285e024caea8a2bd6e590da9`) from
<https://github.com/espressif/crosstool-NG/releases/tag/esp-16.1.0_20260609>. It ships
`xtensa-esp32-elf-*` wrappers next to the `xtensa-esp-elf-*` tools.

```bash
export PATH="<unzipped>/xtensa-esp-elf/bin:$PATH"
./scripts/fetch_third_party.sh                      # Phase I sources
git clone --depth 1 https://github.com/PQClean/PQClean third_party/PQClean
git clone --depth 1 https://github.com/pq-code-package/mlkem-native third_party/mlkem-native
git clone --depth 1 https://github.com/pq-code-package/mldsa-native third_party/mldsa-native
git clone --depth 1 https://github.com/cisco/hash-sigs third_party/hash-sigs
git clone --depth 1 -b v3.6.7 https://github.com/Mbed-TLS/mbedtls third_party/mbedtls-3.6.7   # SHA-256 for hash-sigs
python dataset/gen_lms_keys.py          # only if you want to regenerate lms_pubkeys.h (deterministic)
python dataset/build_pqc.py --toolchain-prefix xtensa-esp32-elf-
python eval/evaluate_pqc.py
```

The revisions in the table above are what the committed images were built from; the repositories
were cloned at their default branch on 2026-10-29, so check out those revisions to reproduce them
byte for byte.

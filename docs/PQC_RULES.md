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
| mlkem-native (ML-KEM-768, C backend) | `08e1f3881ec1` | ML-KEM |
| mldsa-native (ML-DSA-65, C backend) | `f89fc5779656` | ML-DSA |

For every image, `truth.json` records the address and size of the zeta table (symbol found in the
unstripped ELF), and `tests/test_pqc.py::test_derived_table_equals_bytes_of_real_build` compares the
spec-derived table with the bytes at that address in the shipped `firmware.bin`:

- ML-KEM: all 128 entries equal the derived Montgomery table, in all 10 images.
- ML-DSA: entries 1..255 equal the derived table, in all 10 images. Entry 0 is an unused `0` in the
  reference code (the derived value would be `1 * 2^32 mod q`); the rule skips it.

## Results

`python eval/evaluate_pqc.py` writes [`results/RESULTS_pqc.md`](../results/RESULTS_pqc.md). On 20 positive
images and the 198 Phase I images as negatives: ML-KEM 10/10, ML-DSA 10/10, no false positives
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
python dataset/build_pqc.py --toolchain-prefix xtensa-esp32-elf-
python eval/evaluate_pqc.py
```

The revisions in the table above are what the committed images were built from; the repositories
were cloned at their default branch on 2026-10-29, so check out those revisions to reproduce them
byte for byte.

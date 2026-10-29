# Dataset

## Design

Every image is one **application profile** built with one **library variant** at one
**optimisation level**.

| Dimension | Values |
|---|---|
| Profiles (11) | `ota_rsa_pss`, `ota_ecdsa_p256`, `tls_ecdhe_p256_gcm`, `x25519_chachapoly`, `legacy_md5_sha1_3des_rsa`, `ffdh_aes_cbc`, `symmetric_only`, `hwaccel_ecdsa_p384`, `device_identity_rsa2048`, `full_stack`, `noncrypto` |
| Library variants (3) | `m36`: mbedTLS 3.6.7, AES tables generated at run time (default); `m36rom`: same with AES tables in flash; `m228`: mbedTLS 2.28.10 |
| Optimisation (4) | `O0`, `O1`, `O2`, `Os` |
| Secure Boot | `Os` builds also signed with Secure Boot V2 using RSA-3072 and ECDSA P-256 test keys |

132 unsigned + 66 signed = 198 images. Sample names are `<variant>__<opt>__<profile>[__<signing>]`.

Every image also links non-crypto code (miniz compression with its CRC-32/Adler tables, jsmn JSON
parsing, a printf implementation, application logic) so the scanner sees realistic noise. The
`hwaccel_ecdsa_p384` and `full_stack` profiles include a synthetic driver that drives the ESP32
SHA and AES accelerator registers (addresses from the ESP32 TRM peripheral map).

## Files per sample

```
dataset/out/samples/<sample>/
  firmware.bin     ESP32 app image: the scanner input (committed)
  truth.json       ground truth (committed)
  firmware.elf     unstripped ELF with debug info   (rebuild only)
  firmware.map     linker map                       (rebuild only)
  firmware.stripped.elf                             (rebuild only)
```

`dataset/out/index.json` lists every sample with its truth families.

## Ground truth

Truth comes from the linker map: every input section that ends up in the image is attributed to
the object file it came from, and object files map to families (`aes.o` → AES, `ecdsa.o` → ECDSA,
`ecp.o` / `ecp_curves.o` → ECC, ...; mapping in `cbomscan/taxonomy.py`). A family is present when
any of its code or data is linked.

`truth.json` fields:

| Field | Meaning |
|---|---|
| `present_families` | Families whose code is linked (the scoring target) |
| `intended_families` | What the profile's own code calls (for discussion; not scored) |
| `family_ranges` | Address ranges per family, with section name, object and code/data kind |
| `support_ranges` | Address ranges of crypto support code (bignum, OID tables, PK, MD, cipher layers) |
| `family_code_bytes` | Code bytes per family |
| `secure_boot` | `none`, `sbv2_rsa3072` or `sbv2_ecdsa_p256` |
| `variant`, `opt`, `profile`, `toolchain`, `bin_sha256`, `bin_size` | Build metadata |

**Truth is linked capability, not runtime use.** One OTA verification call links RSA, ECDSA, DES,
MD5 and more through mbedTLS's PK, PEM and MD layers, so `present_families` is usually larger than
`intended_families`. That is what a CBOM should report.

## Rebuilding

```bash
sudo apt install gcc-xtensa-lx106 binutils-xtensa-lx106 picolibc-xtensa-lx106-elf
pip install -r requirements.txt
./scripts/fetch_third_party.sh
python dataset/build_dataset.py            # about 10 minutes on 2 cores
python eval/evaluate.py
```

Options: `--variants m36,m228`, `--opts Os`, `--profiles ota_rsa_pss`, `--no-sign`, `--rebuild`,
`--jobs N`, `--out DIR`, `--toolchain-prefix`, `--specs`.

Secure Boot test keys are generated into `dataset/out/_keys/` on first build and are not
committed. They are throwaway keys for the dataset only.

## Toolchain note

Phase I used Ubuntu's `xtensa-lx106-elf` GCC 13.2 (ESP8266 core, call0 ABI) with picolibc,
linked with an ESP32 memory map (`dataset/support/esp32_app.ld`) and packed with
`esptool elf2image --chip esp32`. The images are valid ESP32 app images for static analysis but
do not boot. That toolchain's libgcc lacks some helpers the ESP8266 ROM normally provides, so
`dataset/support/libgcc_shim.c` supplies them.

For Phase II, rebuild with Espressif's `xtensa-esp32-elf-gcc` (windowed ABI), which is what real
ESP32 firmware uses:

```bash
. $IDF_PATH/export.sh
python dataset/build_dataset.py --toolchain-prefix xtensa-esp32-elf- --specs "" --out dataset/out_esp32
```

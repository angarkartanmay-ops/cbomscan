# Held-out test set (P2.2): policy

Written **before** any held-out image is scored and before any Phase II feature or model code exists.
Rules and models are developed on the *development* sets only.

## Sets

| Set | Where | Role |
|---|---|---|
| Phase I dataset | `dataset/out` | development (Ubuntu call0 toolchain; mbedTLS 3.6.7 / 2.28.10; -O0/-O1/-O2/-Os) |
| Espressif rebuild | `dataset/out_esp32` | development (GCC 16.1 windowed ABI; same libraries; adds -O3) |
| Post-quantum images | `dataset/out_pqc` | development for the PQC rules |
| **Held-out** | `dataset/heldout/` | **test only; never used to tune rules, features, thresholds or models** |

## What the held-out set varies, on purpose

The split is by *build configuration*, not by function or by random image, so nothing in the test set shares
a library version, build system or optimisation level with the development sets:

1. **Build system and library integration:** real ESP-IDF v5.5.6 example applications (CMake, Espressif's
   mbedTLS fork and configuration, hardware-accelerated crypto, the full IDF component stack) instead of our
   own link scripts and profiles.
2. **Compiler:** the GCC 14.2.0 shipped with ESP-IDF v5.5.6 (`esp-14.2.0_20260121`); the development sets use
   GCC 13.2 (Ubuntu) and 16.1.
3. **Optimisation level:** `-Og` (ESP-IDF "Debug") is held out entirely; the development sets contain no -Og.
   `-O0`, `-Os` and `-O2` are also built, as ESP-IDF configures them.
4. **Library:** wolfSSL v5.9.4-stable ESP-IDF example apps (`wolfssl_client`, `wolfssl_server`,
   `wolfssl_test`, `wolfssl_benchmark`), built with the same IDF v5.5.6 toolchain and the same four
   optimisation levels. A second crypto library, with none in the development sets.

Apps: ESP-IDF `https_request`, `simple_ota`, `mqtt_ssl`, `https_mbedtls` (mbedTLS) and the four wolfSSL
examples above, each at `-Os`, `-O0`, `-Og`, `-O2` (IDF Kconfig SIZE / NONE / DEBUG / PERF). Each example's own
`sdkconfig.defaults` is used unmodified; only the optimisation level is appended, and at `-O0` the
placement options that let the image link (Wi-Fi/FreeRTOS code in flash, larger single-app partition when the
example sets no partition table). Recipes: `C:\espuild_example.ps1`, `build_wolf.ps1` (outside the repo).

## Attribution rules for the map (fixed before any held-out image was scored)

- mbedTLS (`libmbedcrypto.a`): the Phase I object table plus the ESP-IDF hardware ports
  (`esp_aes*`, `esp_sha1/256/512`). `libwpa_supplicant.a`: `des-internal` is DES, `dh_groups` is FFDH.
- wolfSSL (`libwolfssl.a`): one file is one family where that is true (`aes`, `des3`, `md5`, `sha`, `sha256`,
  `sha512`, `rsa`, `dh`, `chacha`, `poly1305`). `ecc.c` holds three families, so it is ECC, and a live
  `wc_ecc_sign_hash*` / `wc_ecc_verify_hash*` section also counts as ECDSA and `wc_ecc_shared_secret*` as ECDH.
  `esp32_*` hardware drivers, `tfm`, `asn`, `ssl`/`tls`/`internal`, `hmac`, `ed25519`, `curve25519` are support
  or outside the 13 scored families.
- Truth counts only sections the linker kept (non-zero address), so garbage-collected functions do not count.
- Prebuilt Espressif blobs (`libnet80211`, `libphy`, ...) cannot be attributed; that limits the truth.

## Measured property of the mbedTLS half (read before interpreting results)

Checked from the linker maps of the first 16 builds: **all 16 ESP-IDF mbedTLS images have the identical set of
10 families** (AES, MD5, SHA1, SHA256, SHA512, RSA, ECDSA, ECDH, ECC, FFDH), with identical object sizes. This is
real, not an attribution artefact: every app is a TLS client, so IDF pulls in the same mbedTLS objects. The mbedTLS half
therefore tests *detection under a different compiler, build system and optimisation level*, not *which
families are present*. It cannot measure false positives for DES, ChaCha20-Poly1305 or FFDH-absence per app.
The wolfSSL half adds variation (for example DES is linked, and the test/benchmark apps link more algorithms).
Per-family numbers must be read with this in mind.

## Ground truth

Same definition as Phase I: the set of algorithm families whose code is linked into the image, attributed from
the linker map (object file to family). For ESP-IDF builds the map is produced by the IDF build (`*.map`) and
the object names are `libmbedcrypto.a(aes.c.obj)` style, so the mapping in `cbomscan/taxonomy.py` is applied
to those names by `dataset/heldout_truth.py`. Truth is linked capability, not runtime use.

## Freeze procedure

1. Build every held-out image; write `truth.json` next to each `firmware.bin`.
2. Compute `SHA-256` of every `firmware.bin` and `truth.json` into `dataset/heldout/MANIFEST.sha256`.
3. Commit images, truths and the manifest in one commit, and tag it `heldout-frozen-<n>`.
4. `tests/test_heldout_frozen.py` fails if any file differs from the manifest.
5. Held-out results are produced only by `eval/evaluate.py --dataset dataset/heldout --out results/heldout`, and
   each run is recorded in `results/heldout/` with the commit it ran at. Rules or models changed after seeing a
   held-out result must say so in the commit message, and the set is then no longer clean for that component.

## Known limitations of this set

- Few images (tens, not thousands), so per-family numbers will be noisy; report counts, not only rates.
- ESP-IDF example apps use mbedTLS through the same families as the development sets, so this tests
  generalisation across build system, compiler and optimisation level, not across fundamentally different crypto
  implementations (wolfSSL adds some of that).
- Examples are built for ESP32 only; other chips are Phase III.

## Line endings

The manifest was written on Windows, so the text files (`index.json`, `truth.json`) were hashed with CRLF
line endings. A Linux or CI checkout has LF. `tests/test_heldout_frozen.py` accepts either form of the
same file; any other difference still fails. No held-out file was changed.

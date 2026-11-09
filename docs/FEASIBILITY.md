# Migration feasibility (Phase III, P3.1)

For each migration action the scan triggers, cbomscan runs static checks against the image and reports
`ok`, `warn`, `blocked` or `unknown`. Every check states what it measured and what it assumed. The
verdict for an action is its worst check. Code: `cbomscan/feasibility.py`. Tests: `tests/test_feasibility.py`.

It answers "does the image give a reason to expect trouble?", not "will the migration work?".

## Actions and checks

| Action | Triggered by | Checks |
|---|---|---|
| Signatures to ML-DSA-65 (or LMS for firmware signing) | RSA, ECDSA, a Secure Boot V2 block | flash headroom; ESP-IDF version; post-quantum boot verification for this chip; classical ROM verifier |
| Key agreement to hybrid X25519MLKEM768 | ECDH, FFDH, ECC | flash headroom; ESP-IDF version; RAM for TLS buffers |
| Replace MD5, SHA-1, DES/3DES | those families | is SHA-256 / AES already linked |
| 256-bit AES keys | AES | key length (not readable from the image) |

## Inputs and where the numbers come from

| Input | Source |
|---|---|
| Image size | the app image header and segments |
| App partition size | the partition table if the input is a flash dump; otherwise **assumed 1 MB** (ESP-IDF default), and the report says so |
| ESP-IDF version | the app descriptor; the Phase I dataset's `-sim` strings are reported as `unknown` |
| ML-KEM-768 code: 10,585 B | measured: `dataset/out_pqc/samples/mlkem_native768__Os` (mlkem-native, -Os, Espressif GCC 16.1) |
| ML-DSA-65 code: 14,558 B | measured: `dataset/out_pqc/samples/mldsa_native65__Os` (mldsa-native, -Os) |
| LMS verify code: 2,055 B | measured: `dataset/out_pqc/samples/hashsigs_h10_w4__Os` (hash-sigs; also needs SHA-256) |
| ML-DSA-65 public key 1,952 B, signature 3,309 B | FIPS 204 |
| Hybrid key share 1,216 B, ~7.5 KB certificate chains, hybrid Secure Boot ~8 KB flash and ~78 ms | Espressif esp-pqc announcement (`migration.ESP_PQC_SOURCE`) |
| Chips with post-quantum boot verification: ESP32-C3, C5, C6 | same source |

The measured sizes are the bytes of code and read-only data attributed to the library in each build's
linker map. `test_measured_sizes_match_truth_files` re-derives them from the committed `truth.json` files.

## Thresholds

- Flash: `blocked` if image + replacement exceeds the partition; `warn` if less than 10% of the partition
  stays free; otherwise `ok`.
- ESP-IDF: `ok` at v6.0 or later, `warn` below (esp-pqc needs v6.0), `unknown` if no version is recorded.

## What it cannot tell

- **RAM.** Free heap depends on run-time state. The check is always `unknown` and says what to measure.
- **AES key length.** AES-128 and AES-256 share code and tables.
- **Which code path runs.** Presence means linked, not executed.
- **Performance budgets.** Boot and handshake times are quoted from Espressif for the ESP32-C5. They are
  not measured on the scanned device.

## Example (signed full-stack image, ESP32)

Signatures: **blocked**. Flash fits (82% free after), but esp-pqc's post-quantum boot verification does not
support the original ESP32, and the ROM verifier stays classical on every chip. On this chip ML-DSA can protect
OTA updates inside the application, not the boot chain.

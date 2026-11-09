# Board test

`scripts/board_test.py` reads an ESP32's flash over USB with esptool, scans the dump three ways (in-process,
CLI with CycloneDX validation, dashboard server over HTTP) and checks that the in-process and HTTP results match.

## Status

**Not run on hardware.** No ESP32 has been attached to a machine that runs the script. The steps after the
flash read have been rehearsed on a synthetic flash dump. That checks the software path, not the board path.

## Rehearsal (no board)

```bash
python dataset/make_flash_dump.py dataset/out_esp32/samples/m228__Os__full_stack__sbv2_rsa3072/firmware.bin dump.bin
python scripts/board_test.py --dump dump.bin
```

Result on 2026-11-09 (development image, 4 MB dump, factory app at 0x10000):

| Step | Result |
|---|---|
| Load as flash dump, find app partition | ok: `flash-dump`, chip ESP32, app 150,880 bytes, 1 Secure Boot block |
| CLI scan and CycloneDX 1.6 validation | ok |
| Dashboard server `POST /api/scan` | ok |
| In-process result equals HTTP result | True |
| Exit code | 0 |

Families at or above threshold: AES, DES, ChaCha20, MD5, SHA-1, SHA-256, SHA-512, RSA, ECDSA, ECC, FFDH.
Feasibility: signatures **blocked** (ESP32 has no esp-pqc post-quantum boot verification), key agreement
**unknown** (heap cannot be read from an image), weak algorithms **ok** (SHA-256 and AES already linked).

## Running it on a board

1. Install the USB-UART driver for the board (CP210x or CH340, depending on the board).
2. `pip install esptool pyserial`
3. `python scripts/board_test.py --port COM5` (Windows) or `--port /dev/ttyUSB0` (Linux).
4. Record the chip line, the families found and the exit code here, with the date and board model.

A board running firmware with no cryptography will show few findings. That is a correct result, not a failure.

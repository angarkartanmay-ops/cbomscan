# Chip support (Phase III, P3.2)

cbomscan reads the chip from the image header (`image.CHIP_IDS`). Which parts of the scanner are valid depends
on the chip. The scanner now applies only the parts that are valid and says so in the report, the CBOM
(`chipScope` property) and the dashboard.

| Chip | Instruction set | Data rules (constants, OIDs, keys, names, Secure Boot block) | Accelerator-register rules | ML tier |
|---|---|---|---|---|
| ESP32 | Xtensa LX6 | yes | yes (ESP32 TRM addresses) | yes (trained here) |
| ESP32-S2, ESP32-S3 | Xtensa LX7 | yes | skipped | skipped: not validated |
| ESP32-C2, C3, C5, C6, C61, H2, P4 | RISC-V | yes | skipped | skipped: needs a RISC-V disassembler |

## Why this split

- **Data rules** match bytes in data: S-boxes, round constants, OIDs, DER keys, names, the Secure Boot V2
  block. These do not depend on the CPU.
- **Literal-pool rules** find constants that Xtensa code loads with `l32r`. RISC-V builds constants inline with
  `lui`/`addi`, so these rules will find less on RISC-V images. This has not been measured.
- **Accelerator registers** sit at different addresses on each chip. The rules hold ESP32 addresses only, so
  on other chips they could misread an unrelated constant. They are switched off there.
- **The ML tier** was trained on ESP32 windowed-ABI functions. Function recovery looks for the Xtensa
  `entry` instruction, which RISC-V does not have.

## Tested

`tests/test_feasibility.py::test_other_chip_skips_esp32_only_rules` changes the chip ID of an ESP32 image to
ESP32-C3 and checks that register rules are skipped, a note is added, and the boot-verification check changes
to `ok` (esp-pqc supports C3). **No real S2, S3 or RISC-V image has been scanned.**

## To extend

1. Build test images for an ESP32-C3 (RISC-V) and an ESP32-S3 with ESP-IDF, with linker maps for truth.
2. Measure the data rules on them before claiming support.
3. Add accelerator addresses per chip from each Technical Reference Manual, with a test per chip.
4. For the ML tier on RISC-V: a RISC-V disassembler (Capstone supports it) and function recovery from
   call targets, then retraining.

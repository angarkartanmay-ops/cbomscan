# Xtensa disassembly backend (P2.3)

`cbomscan/disasm.py` turns a code byte string into `Insn(address, size, mnemonic, operands, raw, source)`.
It is the input of function boundary recovery (P2.4) and feature extraction (P2.6). Tier 1 does not use it.

## Options evaluated

| Option | What was found | Verdict |
|---|---|---|
| **GNU objdump** from Espressif's toolchain (`xtensa-esp32-elf-objdump`) | Correct by construction for compiled code (it is the toolchain's own disassembler), but needs the 247 MB toolchain on every machine, a subprocess per image and text parsing. It also mis-decodes inline literal data as instructions (`lsi`, `s32ri`, `f64*`). | Used as the **ground truth** in tests and evaluation, not as the runtime backend |
| **Capstone 6** (`capstone==6.0.0a11`) | `pip`-installable wheel with an Xtensa backend (`CS_MODE_XTENSA_ESP32`, also S2/S3/ESP8266 modes). Stable Capstone 5.0.9 has no Xtensa. Where it decodes, its mnemonics equal objdump's. Gaps measured below: it stops at `beqz.n`, `bnez.n` and `nop.n`, and decodes some `movi.n` as `break.n`. It is a pre-release, so the pin matters. | **Chosen** as the general-purpose decoder |
| **Own decoder for the whole ISA** | Not built: a large table-driven job that Capstone already covers, with a correctness risk we would have to burn down against objdump anyway. | Rejected for now |
| **Own decoder for the narrow gap group only** | `movi.n`, `beqz.n`, `bnez.n`, `nop.n` (16-bit "density" forms; layout in the docstring of `_decode_narrow`). Small enough to verify exhaustively. | **Chosen** to patch Capstone |

Decision: Capstone 6 + a 25-line decoder for the four narrow forms + the Xtensa length rule
(`op0` in 0x8..0xD means 16-bit, otherwise 24-bit) to stay in step on anything undecoded. An undecoded
instruction is returned with `mnemonic=None` and `source="unknown"`, never dropped.

## Measured agreement with objdump

`python eval/check_disasm.py` (needs the toolchain's objdump; writes [`results/DISASM.md`](../results/DISASM.md)).
Ground truth: every function (by ELF symbol) of the 45 unstripped post-quantum images built with Espressif
GCC 16.1 (windowed ABI) at -O0/-O1/-O2/-Os/-O3: 2 651 functions, 207 224 instructions.

| | Agreement |
|---|---|
| Instruction address and size | 99.84 % |
| Mnemonic (special-register suffixes folded: `rsr.sar` = `rsr`) | 99.46 % |
| Returned as undecoded | 0.38 % (793 instructions) |
| Own narrow decoder: operands identical to objdump | 8 902 / 8 902 |

Per optimisation level the mnemonic agreement is between 99.16 % (-O3) and 99.72 % (-O0).

What the residue is, as far as we know:

- **Undecoded (793):** 499 are in a run that starts immediately after an unconditional `j` or `ret`, where
  control cannot fall through; this is consistent with literal-pool words the compiler placed inside the
  code stream (objdump mis-decodes the same bytes as `lsi`, `s32ri`, `f64*`). Traced by hand for one
  case, not proved for all. The other 294 were not characterised.
- **Boundary disagreements (0.16 %):** instructions after inline data, where a linear sweep cannot know
  it is looking at data and may need a few instructions to realign.
- **Consequence for later work:** disassemble functions (after P2.4), not whole segments, and treat an
  undecoded run after a `j`/`ret` as data when building features.

## Tests

`tests/test_disasm.py` runs without the toolchain against `tests/data/disasm_golden.json`: objdump's recorded
output for 36 functions (1 577 instructions) chosen mechanically from three images
(`eval/make_disasm_golden.py`), plus real bytes from an unstripped build. It checks boundaries, mnemonics, the
narrow decoder's operands, that `entry` marks function starts as in objdump, and that undecoded data is
reported rather than hidden.

## Limits

- Only the ESP32 (LX6) mode and the windowed ABI were checked. The Capstone S2/S3/ESP8266 modes exist but
  were not evaluated; the Phase I images (call0 ABI, ESP8266 core) were not re-checked because their ELFs
  are not shipped.
- Only GCC-generated code was checked (Espressif GCC 16.1, no FLIX/vector or ESP32-S3 SIMD code).
- Capstone 6.0.0a11 is a pre-release; behaviour may change in later releases. Re-run
  `eval/check_disasm.py` before bumping the pin.

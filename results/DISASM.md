# Disassembly check against objdump (P2.3)

2651 functions from the unstripped ELFs under `out_pqc` (Espressif GCC 16.1, windowed ABI), compared with that toolchain's objdump.

| Opt | Instructions | Boundary+size agree | Mnemonic agree | Undecoded | Own-decoder operands agree |
|---|---|---|---|---|---|
| O0 | 70419 | 1.0000 | 0.9972 | 0.0027 | 3300/3300 |
| O1 | 29111 | 0.9992 | 0.9941 | 0.0052 | 1430/1430 |
| O2 | 35065 | 0.9960 | 0.9929 | 0.0032 | 1281/1281 |
| O3 | 45144 | 0.9967 | 0.9916 | 0.0051 | 1580/1580 |
| Os | 27485 | 0.9994 | 0.9955 | 0.0039 | 1311/1311 |
| **all** | 207224 | 0.9984 | 0.9946 | 0.0038 | 8902/8902 |

objdump data directives (`.byte` etc., e.g. jump tables) inside function ranges, excluded from the instruction counts above: 64. A linear sweep cannot know about them, so instructions right after such data can be mis-aligned until the stream resynchronises; those show up under boundary disagreements.

Of the 793 undecoded instructions, 499 are in a run that starts right after an unconditional jump or return (`j`, `ret*`). Control cannot fall into those bytes, which is consistent with inline literal-pool words the compiler placed in the code stream (objdump mis-decodes them as `lsi`, `s32ri`, `f64*`...). This is an inference from control flow; it was traced by hand for one case (`j` over 4 bytes at 0x400d0b74 in hashsigs_nokey__Os), not proved for all.

Decoded by: Capstone 197200, own narrow decoder 8902, unknown 793.

## Disagreements (objdump mnemonic -> ours)

- `lsi` -> `<undecoded>`: 725
- `f64cmph` -> `<undecoded>`: 36
- `s32ri` -> `<undecoded>`: 15
- `l32ai` -> `<undecoded>`: 9
- `f64norm` -> `<undecoded>`: 3
- `f64iter` -> `<undecoded>`: 2
- `f64subc` -> `<undecoded>`: 1
- `f64sexp` -> `<undecoded>`: 1
- `break.n` -> `<undecoded>`: 1

## Instructions whose address or size we did not reproduce (objdump mnemonic)

- `s32i`: 90
- `l32r`: 78
- `callx12`: 15
- `movi.n`: 14
- `mov.n`: 13
- `retw.n`: 12
- `addmi`: 11
- `add.n`: 9
- `l8ui`: 9
- `lsi`: 8

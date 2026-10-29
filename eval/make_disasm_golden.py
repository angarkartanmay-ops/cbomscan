#!/usr/bin/env python3
"""Record objdump's disassembly of known functions as a test fixture (tests/data/disasm_golden.json).

Needs the Espressif toolchain's objdump. Selection is mechanical and made without looking at our decoder:
from three unstripped dataset ELFs (different libraries and optimisation levels), functions of 40..400
bytes, taking 12 evenly spaced by address from each. Re-run only to regenerate the fixture.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
import check_disasm as cd  # noqa: E402

ELFS = ["pqclean_mlkem768__O2", "hashsigs_nokey__Os", "mldsa_native65__O0"]
PER_ELF = 12


def main():
    out = []
    for name in ELFS:
        elf = ROOT / "dataset/out_pqc/samples" / name / "firmware.elf"
        od = cd.objdump(elf, "xtensa-esp32-elf-objdump")
        e, fl = cd.functions(elf)
        cand = [f for f in fl if 40 <= f[1] <= 400]
        step = max(1, len(cand) // PER_ELF)
        for addr, size, fname in cand[::step][:PER_ELF]:
            ins = [[x, v[0], v[1], v[2]] for x, v in sorted(od.items())
                   if addr <= x < addr + size and not v[1].startswith(".")]
            out.append({"image": name, "function": fname, "address": addr,
                        "code": cd.code_at(e, addr, size).hex(), "objdump": ins})
    path = ROOT / "tests/data/disasm_golden.json"
    path.write_text(json.dumps(out, separators=(",", ":")))
    print(f"{len(out)} functions, {sum(len(f['objdump']) for f in out)} instructions -> {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()

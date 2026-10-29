#!/usr/bin/env python3
"""Compare cbomscan.disasm with Espressif's objdump on every function of the unstripped dataset ELFs (P2.3).

Needs xtensa-esp32-elf-objdump on PATH (the ground truth), pyelftools and Capstone 6.
Function ranges come from the ELF symbol table, so literal pools and jump tables are not decoded.
Writes results/DISASM.md. Mnemonic comparison folds objdump's special-register suffixes
(rsr.acclo, wsr.sar, xsr.lcount ...) to the Capstone form (rsr, wsr, xsr).
"""

import argparse
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from elftools.elf.elffile import ELFFile  # noqa: E402

from cbomscan.disasm import disassemble  # noqa: E402

LINE = re.compile(r"\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*\t(\S+)(?:\t(.*))?$")
UNCOND = {"j", "j.l", "jx", "ret", "ret.n", "retw", "retw.n", "retw.n", "rfe", "rfi", "rfde"}
FOLD = re.compile(r"^(rsr|wsr|xsr|rur|wur)\.\w+$")


def objdump(elf, tool):
    txt = subprocess.run([tool, "-d", str(elf)], capture_output=True, text=True, check=True).stdout
    ins = {}
    for line in txt.splitlines():
        m = LINE.match(line)
        if m:
            ins[int(m.group(1), 16)] = (len(m.group(2).replace(" ", "")) // 2, m.group(3), (m.group(4) or "").split(" <")[0])
    return ins


def functions(elf):
    f = open(elf, "rb")
    e = ELFFile(f)
    out = [(s["st_value"], s["st_size"], s.name) for s in e.get_section_by_name(".symtab").iter_symbols()
           if s["st_info"]["type"] == "STT_FUNC" and s["st_size"] > 0]
    return e, sorted(out)


def code_at(e, addr, n):
    for seg in e.iter_segments():
        if seg["p_type"] == "PT_LOAD" and seg["p_vaddr"] <= addr < seg["p_vaddr"] + seg["p_filesz"]:
            o = addr - seg["p_vaddr"]
            return seg.data()[o:o + n]
    raise KeyError(hex(addr))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default=str(ROOT / "dataset/out_pqc"))
    ap.add_argument("--objdump", default="xtensa-esp32-elf-objdump")
    ap.add_argument("--out", default=str(ROOT / "results"))
    a = ap.parse_args()
    rows = defaultdict(lambda: Counter())
    missing = Counter()
    mism = Counter()
    nfunc = 0
    for d in sorted((Path(a.dataset) / "samples").iterdir()):
        elf = d / "firmware.elf"
        if not elf.exists():
            continue
        opt = d.name.rsplit("__", 1)[1]
        od = objdump(elf, a.objdump)
        e, fl = functions(elf)
        for addr, size, _ in fl:
            nfunc += 1
            ref = {x: v for x, v in od.items() if addr <= x < addr + size and not v[1].startswith(".")}
            inline_data = sum(1 for x, v in od.items() if addr <= x < addr + size and v[1].startswith("."))
            rows[opt]["inline_data_lines"] += inline_data
            got = {i.address: i for i in disassemble(code_at(e, addr, size), addr)}
            c = rows[opt]
            ordered = sorted(ref)
            in_data_run = False   # previous objdump instruction ended the flow and we are inside an undecodable run
            prev = None
            for x in ordered:
                rs, rm, rops = ref[x]
                g0 = got.get(x)
                undec = g0 is not None and g0.size == rs and g0.mnemonic is None
                if undec and (in_data_run or (prev is not None and prev in UNCOND)):
                    in_data_run = True
                    c["undecoded_after_uncond_transfer"] += 1
                elif not undec:
                    in_data_run = False
                prev = rm
            for x, (rs, rm, rops) in ref.items():
                c["insns"] += 1
                g = got.get(x)
                if g is None or g.size != rs:
                    c["boundary_wrong"] += 1
                    missing[rm] += 1
                    continue
                c["boundary_ok"] += 1
                c["src_" + g.source] += 1
                if g.mnemonic is None:
                    c["undecoded"] += 1
                    mism[(rm, "<undecoded>")] += 1
                elif g.mnemonic == FOLD.sub(lambda m: m.group(1), rm):
                    c["mnemonic_ok"] += 1
                else:
                    c["mnemonic_wrong"] += 1
                    mism[(rm, g.mnemonic)] += 1
                if g.source == "own":
                    c["own"] += 1
                    c["own_operands_ok"] += g.operands == rops
    tot = Counter()
    for c in rows.values():
        tot.update(c)
    pc = lambda k, c=tot: c[k] / c["insns"] if c["insns"] else float("nan")
    L = ["# Disassembly check against objdump (P2.3)", "",
         f"{nfunc} functions from the unstripped ELFs under `{Path(a.dataset).name}` "
         "(Espressif GCC 16.1, windowed ABI), compared with that toolchain's objdump.", "",
         "| Opt | Instructions | Boundary+size agree | Mnemonic agree | Undecoded | Own-decoder operands agree |",
         "|---|---|---|---|---|---|"]
    for opt in sorted(rows):
        c = rows[opt]
        L.append(f"| {opt} | {c['insns']} | {c['boundary_ok'] / c['insns']:.4f} | {c['mnemonic_ok'] / c['insns']:.4f} | "
                 f"{c['undecoded'] / c['insns']:.4f} | {c['own_operands_ok']}/{c['own']} |")
    L.append(f"| **all** | {tot['insns']} | {pc('boundary_ok'):.4f} | {pc('mnemonic_ok'):.4f} | {pc('undecoded'):.4f} | "
             f"{tot['own_operands_ok']}/{tot['own']} |")
    L += ["", f"objdump data directives (`.byte` etc., e.g. jump tables) inside function ranges, excluded from the "
              f"instruction counts above: {tot['inline_data_lines']}. A linear sweep cannot know about them, so "
              "instructions right after such data can be mis-aligned until the stream resynchronises; those show up "
              "under boundary disagreements.", "",
          f"Of the {tot['undecoded']} undecoded instructions, {tot['undecoded_after_uncond_transfer']} are in a run that "
          "starts right after an unconditional jump or return (`j`, `ret*`). Control cannot fall into those bytes, "
          "which is consistent with inline literal-pool words the compiler placed in the code stream (objdump "
          "mis-decodes them as `lsi`, `s32ri`, `f64*`...). This is an inference from control flow; it was traced "
          "by hand for one case (`j` over 4 bytes at 0x400d0b74 in hashsigs_nokey__Os), not proved for all.", "",
          f"Decoded by: Capstone {tot['src_capstone']}, own narrow decoder {tot['src_own']}, "
              f"unknown {tot['src_unknown']}.", "",
          "## Disagreements (objdump mnemonic -> ours)", ""]
    L += [f"- `{k[0]}` -> `{k[1]}`: {v}" for k, v in mism.most_common(15)] or ["- none"]
    if missing:
        L += ["", "## Instructions whose address or size we did not reproduce (objdump mnemonic)", ""]
        L += [f"- `{k}`: {v}" for k, v in missing.most_common(10)]
    out = Path(a.out)
    (out / "DISASM.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()

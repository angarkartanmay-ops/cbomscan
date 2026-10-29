"""Xtensa disassembly wrapper (P2.3), checked against recorded objdump output of real functions."""

import json
import re
from pathlib import Path

import pytest

capstone = pytest.importorskip("capstone")
if not hasattr(capstone, "CS_ARCH_XTENSA"):
    pytest.skip("Capstone without Xtensa support (need capstone==6.0.0a11)", allow_module_level=True)

from cbomscan.disasm import disassemble, insn_length  # noqa: E402

GOLDEN = json.loads((Path(__file__).parent / "data" / "disasm_golden.json").read_text())
FOLD = re.compile(r"^(rsr|wsr|xsr|rur|wur)\.\w+$")


def _run(fn):
    code = bytes.fromhex(fn["code"])
    return {i.address: i for i in disassemble(code, fn["address"])}


# 14 real bytes from hashsigs_nokey__Os at 0x400d0b6c: movi.n, l32i, s32i, j, then 3 bytes of inline literal data
REAL = bytes.fromhex("0c6f" "32214e" "f26152" "c60000" "004261")


def test_real_bytes_decode_and_data_is_reported_not_hidden():
    ins = disassemble(REAL, 0x400D0B6C)
    assert [(i.address, i.size, i.mnemonic, i.source) for i in ins] == [
        (0x400D0B6C, 2, "movi.n", "own"), (0x400D0B6E, 3, "l32i", "capstone"), (0x400D0B71, 3, "s32i", "capstone"),
        (0x400D0B74, 3, "j", "capstone"), (0x400D0B77, 3, None, "unknown")]
    assert ins[0].operands == "a15, 6" and ins[1].operands == "a3, a1, 0x138"
    assert ins[4].text == ".undecoded"          # objdump mis-decodes these data bytes as `lsi`


def test_entry_marks_function_start_like_objdump():
    """P2.4 will use `entry` (windowed ABI) as the function-start marker; it must agree with objdump."""
    n = 0
    for fn in GOLDEN:
        ins = disassemble(bytes.fromhex(fn["code"]), fn["address"])
        if fn["objdump"][0][2] == "entry":
            n += 1
            assert ins[0].mnemonic == "entry" and ins[0].size == 3, fn["function"]
    assert n >= 30


def test_narrow_group_each_mnemonic_reproduces_objdump():
    seen = set()
    for fn in GOLDEN:
        code = bytes.fromhex(fn["code"])
        for addr, size, mn, ops in fn["objdump"]:
            if mn in ("movi.n", "beqz.n", "bnez.n", "nop.n") and mn not in seen:
                i = disassemble(code[addr - fn["address"]:][:size], addr)[0]
                assert (i.mnemonic, i.operands, i.source) == (mn, ops, "own")
                seen.add(mn)
    assert seen == {"movi.n", "beqz.n", "bnez.n", "nop.n"} or seen >= {"movi.n", "beqz.n"}


def test_length_rule():
    assert [insn_length(b) for b in (0x36, 0x0C, 0x1D, 0x0D, 0x08, 0x0E, 0x05)] == [3, 2, 2, 2, 2, 3, 3]


def test_golden_instruction_boundaries_and_sizes():
    total = wrong = 0
    for fn in GOLDEN:
        got = _run(fn)
        for addr, size, _, _ in fn["objdump"]:
            total += 1
            g = got.get(addr)
            wrong += not (g and g.size == size)
    assert total > 1000
    assert wrong / total <= 0.005, f"{wrong}/{total} instruction boundaries differ from objdump"


def test_golden_mnemonics_and_own_operands():
    total = same = undecoded = own = own_ok = 0
    for fn in GOLDEN:
        got = _run(fn)
        for addr, size, mn, ops in fn["objdump"]:
            g = got.get(addr)
            if not (g and g.size == size):
                continue
            total += 1
            undecoded += g.mnemonic is None
            same += g.mnemonic == FOLD.sub(lambda m: m.group(1), mn)
            if g.source == "own":
                own += 1
                own_ok += g.operands == ops
    assert own > 100 and own_ok == own, "own narrow decoder must reproduce objdump operands exactly"
    assert same / total >= 0.99
    assert undecoded / total <= 0.01

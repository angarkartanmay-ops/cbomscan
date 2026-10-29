"""Xtensa (ESP32) disassembly: turn a code byte string into a list of instructions (P2.3).

Backend choice and measurements: docs/DISASM.md. In short:

* general instruction set: Capstone 6 (``pip install capstone==6.0.0a11``, a pre-release; stable
  Capstone 5 has no Xtensa support). Where it decodes, its mnemonics agree with Espressif's objdump.
* the narrow ``movi.n`` / ``beqz.n`` / ``bnez.n`` / ``nop.n`` group is decoded here, because Capstone
  stops at ``beqz.n``/``bnez.n``/``nop.n`` and mis-decodes some ``movi.n`` as ``break.n``. The decode
  was checked against objdump on every instance in the dataset (docs/DISASM.md).
* anything neither decoder handles (for example some floating-point loads) is reported as
  ``mnemonic=None`` with a size from the Xtensa length rule, so the instruction stream stays in step.
  Unknowns are counted, never hidden.

Capstone is imported lazily so the Tier 1 scanner works without it.
"""

from dataclasses import dataclass
from typing import List, Optional

CAPSTONE_REQUIREMENT = "capstone==6.0.0a11"

_CS_CACHE = {}


@dataclass(frozen=True)
class Insn:
    address: int
    size: int
    mnemonic: Optional[str]      # None: undecoded (size still correct by the length rule)
    operands: str
    raw: bytes
    source: str                  # "capstone", "own" or "unknown"

    @property
    def text(self):
        return f"{self.mnemonic or '.undecoded'} {self.operands}".strip()


def _capstone(chip="esp32"):
    if chip in _CS_CACHE:
        return _CS_CACHE[chip]
    try:
        import capstone as cs
    except ImportError as e:  # pragma: no cover - exercised only without capstone
        raise RuntimeError(f"Xtensa disassembly needs Capstone 6: pip install {CAPSTONE_REQUIREMENT}") from e
    modes = {"esp32": "CS_MODE_XTENSA_ESP32", "esp32s2": "CS_MODE_XTENSA_ESP32S2",
             "esp32s3": "CS_MODE_XTENSA_ESP32S3", "esp8266": "CS_MODE_XTENSA_ESP8266"}
    if not hasattr(cs, "CS_ARCH_XTENSA") or chip not in modes or not hasattr(cs, modes[chip]):
        raise RuntimeError(f"installed Capstone has no Xtensa/{chip} support; pip install {CAPSTONE_REQUIREMENT}")
    md = cs.Cs(cs.CS_ARCH_XTENSA, getattr(cs, modes[chip]) | cs.CS_MODE_LITTLE_ENDIAN)
    _CS_CACHE[chip] = md
    return md


def insn_length(first_byte: int) -> int:
    """Xtensa instruction length from op0 (low nibble of byte 0): 0x8..0xD are 16-bit, otherwise 24-bit."""
    return 2 if 8 <= (first_byte & 0xF) <= 13 else 3


def _decode_narrow(code, off, addr):
    """The narrow group Capstone gets wrong. Returns (mnemonic, operands) or None.

    16-bit little-endian word w: op0=w[3:0], t=w[7:4], s=w[11:8], r=w[15:12].
    op0 0xC: t[3]==0 -> movi.n as, imm7 (imm7 = t[2:0]:r, signed, range -32..95);
             otherwise beqz.n (t[2]==0) / bnez.n (t[2]==1) as, pc+4+imm6 with imm6 = t[1:0]:r.
    op0 0xD with r=0xF, s=0, t=3 -> nop.n.
    """
    w = code[off] | (code[off + 1] << 8)
    op0, t, s, r = w & 0xF, (w >> 4) & 0xF, (w >> 8) & 0xF, (w >> 12) & 0xF
    if op0 == 0xC:
        if (t & 0x8) == 0:
            imm = ((t & 0x7) << 4) | r
            return "movi.n", f"a{s}, {imm - 128 if imm >= 96 else imm}"
        imm6 = ((t & 0x3) << 4) | r
        return ("bnez.n" if t & 0x4 else "beqz.n"), f"a{s}, {addr + 4 + imm6:x}"
    if op0 == 0xD and r == 0xF and s == 0 and t == 3:
        return "nop.n", ""
    return None


def disassemble(code: bytes, address: int, chip: str = "esp32") -> List[Insn]:
    """Linear-sweep disassembly of ``code`` loaded at ``address``.

    Use it on code only (a function, or a code run after boundary recovery). A raw sweep over a whole
    segment also decodes literal pools and jump tables as if they were instructions.
    """
    md = _capstone(chip)
    out: List[Insn] = []
    off = 0
    n = len(code)
    while off + 2 <= n:
        size = insn_length(code[off])
        if off + size > n:
            break
        a = address + off
        nar = _decode_narrow(code, off, a) if size == 2 else None
        if nar:
            out.append(Insn(a, 2, nar[0], nar[1], bytes(code[off:off + 2]), "own"))
            off += 2
            continue
        got = next(md.disasm(bytes(code[off:off + 4]), a, count=1), None)
        if got is not None and got.size == size:
            out.append(Insn(a, size, got.mnemonic, got.op_str, bytes(code[off:off + size]), "capstone"))
        else:
            out.append(Insn(a, size, None, "", bytes(code[off:off + size]), "unknown"))
        off += size
    return out


def disassemble_segment(segment, chip: str = "esp32") -> List[Insn]:
    """Disassemble a ``cbomscan.image`` code segment (see the caveat on ``disassemble``)."""
    return disassemble(segment.data, segment.addr, chip)

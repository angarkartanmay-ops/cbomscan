"""Function boundary recovery for stripped Xtensa (ESP32, windowed ABI) images (P2.4).

Rule, derived from the symbol tables of the development images (see eval/eval_functions.py, docs/FUNCTIONS.md):
a function starts at a 4-byte-aligned ``entry a1, imm`` (bytes ``36 x1 yy``: op0=6, n=3 -> ENTRY, s=1).
A function ends where the next recovered one starts (or at the end of the code segment); the end
therefore includes trailing literal pools and padding, and is only an upper bound.

Limits, all measured not assumed: functions without ``entry`` (hand-written assembly, call0 ABI images
as in Phase I) are not found; ``entry``-shaped bytes inside literal data produce false starts.
"""

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Function:
    start: int
    end: int          # exclusive; upper bound (includes trailing literals / padding)

    @property
    def size(self):
        return self.end - self.start


def is_entry(b0: int, b1: int) -> bool:
    """``entry a1, imm12``: byte 0 = 0x36 (op0 = 6, n = 3, m = 0) and s = 1 (low nibble of byte 1)."""
    return b0 == 0x36 and (b1 & 0x0F) == 0x01


def recover_starts(data: bytes, addr: int, align: int = 4) -> List[int]:
    out = []
    for off in range(0, len(data) - 2, align):
        if is_entry(data[off], data[off + 1]) and (addr + off) % align == 0:
            out.append(addr + off)
    return out


RETW_N = bytes.fromhex("1df0")        # retw.n
RETW = bytes.fromhex("900000")        # retw


def _after_return(data: bytes, off: int) -> bool:
    """True when the bytes just before ``off`` end a function: retw.n or retw, optionally followed by up
    to 3 zero padding bytes (the toolchain aligns functions to 4)."""
    for pad in range(0, 4):
        e = off - pad
        if pad and data[e:off].strip(bytes(1)):
            break
        if e >= 2 and data[e - 2:e] == RETW_N:
            return True
        if e >= 3 and data[e - 3:e] == RETW:
            return True
    return False


def filter_by_sweep(data: bytes, addr: int, starts: List[int]) -> List[int]:
    """Drop candidates that fall inside an instruction of the stream swept from the previous start.

    The sweep uses only the Xtensa length rule (op0 8..13 -> 2 bytes, else 3). A candidate is kept when the
    sweep lands exactly on it, or, because literal pools inside a function desynchronise a sweep, when the
    code right before it ends in a return. Either way the sweep restarts at the kept candidate.
    """
    from .disasm import insn_length
    kept: List[int] = []
    pos = None
    for c in starts:
        if pos is None:
            kept.append(c)
            pos = c
            continue
        o = pos - addr
        while pos < c and o < len(data):
            pos += insn_length(data[o])
            o = pos - addr
        if pos == c or _after_return(data, c - addr):
            kept.append(c)
            pos = c
    return kept


def recover_functions(fw, sweep: bool = True) -> List[Function]:
    """Recover functions from the code segments of a ``cbomscan.image.Firmware``."""
    funcs: List[Function] = []
    for seg in fw.segments:
        if seg.kind != "code":
            continue
        starts = recover_starts(seg.data, seg.addr)
        if sweep:
            starts = filter_by_sweep(seg.data, seg.addr, starts)
        for i, s in enumerate(starts):
            e = starts[i + 1] if i + 1 < len(starts) else seg.end
            funcs.append(Function(s, e))
    return funcs

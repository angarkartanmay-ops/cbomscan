"""Per-function features for the Phase II classifier (P2.6). Needs numpy and Capstone (requirements-phase2.txt).

Two groups, kept separate so the ablation can switch each off:

* ``ins``   instruction features: shape statistics (size, loop instructions, shift/rotate/xor/mul density, ...)
            and hashed mnemonic uni-, bi- and tri-gram frequencies.
* ``const`` literal-constant features: the 32-bit values loaded with ``l32r`` (resolved through the image, so they
            are found wherever the toolchain put the literal pool: inline, as in the development images, or in
            ``.literal`` sections, as in ESP-IDF builds), as a hashed bag plus entropy statistics.

Hashing uses zlib.crc32 / integer arithmetic (deterministic across runs, unlike Python's ``hash``).
"""

import zlib
from typing import List, Tuple

import numpy as np

from .disasm import disassemble

N_UNI, N_BI, N_TRI, N_CONST = 128, 256, 256, 256
MAX_BYTES = 8192

SHIFT = {"slli", "srli", "srai", "sll", "srl", "sra", "src", "ssl", "ssr", "ssai", "ssa8l", "ssa8b", "extui", "sext"}
BITWISE = {"xor", "and", "or", "neg", "abs"}
MUL = {"mull", "mul16s", "mul16u", "muluh", "mulsh", "mulaa.dd.ll", "quou", "remu", "quos", "rems"}
LOOP = {"loop", "loopnez", "loopgtz"}
LOAD = {"l8ui", "l16ui", "l16si", "l32i", "l32i.n", "l32r"}
STORE = {"s8i", "s16i", "s32i", "s32i.n"}
CALL = {"call0", "call4", "call8", "call12", "callx0", "callx4", "callx8", "callx12"}
BRANCH_PREFIX = ("b", "j")

SHAPE_NAMES = ["size", "n_insn", "n_undecoded", "n_loop", "f_shift", "f_bitwise", "f_mul", "f_load", "f_store",
               "f_call", "f_branch", "n_l32r", "n_lit_hi", "mean_popcount_lit", "n_distinct_lit"]
NAMES = (SHAPE_NAMES + [f"uni{i}" for i in range(N_UNI)] + [f"bi{i}" for i in range(N_BI)]
         + [f"tri{i}" for i in range(N_TRI)] + [f"const{i}" for i in range(N_CONST)])
# indices 0..10 are instruction-shape statistics, 11..14 literal statistics (see SHAPE_NAMES)
GROUPS = {
    "ins": list(range(0, 11)) + [i for i, n in enumerate(NAMES) if n.startswith(("uni", "bi", "tri"))],
    "const": list(range(11, 15)) + [i for i, n in enumerate(NAMES) if n.startswith("const")],
}


def _h(s: str, mod: int) -> int:
    return zlib.crc32(s.encode()) % mod


def l32r_target(address: int, raw: bytes) -> int:
    """``l32r``: pc-relative literal, ((pc + 3) & ~3) + sign-extended (imm16 << 2) (validated against Capstone)."""
    imm16 = raw[1] | (raw[2] << 8)
    return ((address + 3) & ~3) + ((imm16 - 0x10000) << 2)


def function_vector(fw, start: int, end: int) -> np.ndarray:
    data = fw.read(start, min(end - start, MAX_BYTES)) or b""
    ins = disassemble(data, start)
    v = np.zeros(len(NAMES), dtype=np.float32)
    n = len(ins)
    if n == 0:
        return v
    mn = [i.mnemonic or "undec" for i in ins]
    lits = []
    for i in ins:
        if i.mnemonic == "l32r" and len(i.raw) == 3:
            w = fw.read(l32r_target(i.address, i.raw), 4)
            if w is not None and len(w) == 4:
                lits.append(int.from_bytes(w, "little"))
    c = lambda s: sum(1 for m in mn if m in s)  # noqa: E731
    v[0] = end - start
    v[1] = n
    v[2] = mn.count("undec")
    v[3] = c(LOOP)
    v[4] = c(SHIFT) / n
    v[5] = c(BITWISE) / n
    v[6] = c(MUL) / n
    v[7] = c(LOAD) / n
    v[8] = c(STORE) / n
    v[9] = c(CALL) / n
    v[10] = sum(1 for m in mn if m.startswith(BRANCH_PREFIX) and m not in CALL) / n
    v[11] = len(lits)
    hi = [w for w in lits if 10 <= bin(w).count("1") <= 22]
    v[12] = len(hi)
    v[13] = (sum(bin(w).count("1") for w in lits) / len(lits)) if lits else 0.0
    v[14] = len(set(lits))
    o = len(SHAPE_NAMES)
    for m in mn:
        v[o + _h(m, N_UNI)] += 1.0 / n
    o2 = o + N_UNI
    for a, b in zip(mn, mn[1:]):
        v[o2 + _h(a + "|" + b, N_BI)] += 1.0 / n
    o3 = o2 + N_BI
    for a, b, d in zip(mn, mn[1:], mn[2:]):
        v[o3 + _h(a + "|" + b + "|" + d, N_TRI)] += 1.0 / n
    o4 = o3 + N_TRI
    for w in hi:
        v[o4 + (((w * 2654435761) & 0xFFFFFFFF) >> 24) % N_CONST] += 1.0
    return v


def image_features(fw, funcs) -> Tuple[np.ndarray, List[int]]:
    """Feature matrix (one row per recovered function) and the function start addresses."""
    X = np.zeros((len(funcs), len(NAMES)), dtype=np.float32)
    for k, f in enumerate(funcs):
        X[k] = function_vector(fw, f.start, f.end)
    return X, [f.start for f in funcs]

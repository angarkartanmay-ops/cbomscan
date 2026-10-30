import re
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
pytest.importorskip("capstone")
from cbomscan import image, mlfeatures as mf  # noqa: E402
from cbomscan.disasm import disassemble  # noqa: E402
from cbomscan.functions import recover_functions  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "dataset" / "out_esp32" / "samples" / "m36__O2__full_stack" / "firmware.bin"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="image missing")


def test_groups_are_disjoint_and_cover_distinct_features():
    assert not set(mf.GROUPS["ins"]) & set(mf.GROUPS["const"])
    assert len(mf.NAMES) == mf.N_UNI + mf.N_BI + mf.N_TRI + mf.N_CONST + len(mf.SHAPE_NAMES)


def test_l32r_target_equals_capstone_operand_on_real_code():
    fw = image.load(str(BIN))
    checked = 0
    for f in recover_functions(fw)[:60]:
        for i in disassemble(fw.read(f.start, min(f.size, 4096)), f.start):
            if i.mnemonic == "l32r":
                m = re.search(r"0x([0-9a-f]+)\s*$", i.operands)
                assert int(m.group(1), 16) == mf.l32r_target(i.address, i.raw)
                checked += 1
    assert checked > 20


def test_features_are_deterministic_and_finite():
    fw = image.load(str(BIN))
    fs = recover_functions(fw)[:20]
    a, _ = mf.image_features(fw, fs)
    b, _ = mf.image_features(fw, fs)
    assert a.shape == (20, len(mf.NAMES)) and np.array_equal(a, b) and np.isfinite(a).all()
    assert (a[:, 1] > 0).all()           # every recovered function decodes at least one instruction

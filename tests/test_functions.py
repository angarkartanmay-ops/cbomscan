import json
from pathlib import Path

import pytest

from cbomscan import image
from cbomscan.functions import filter_by_sweep, is_entry, recover_functions, recover_starts

ROOT = Path(__file__).resolve().parent.parent
ENTRY = bytes.fromhex("360100")      # entry a1, 0
RETWN = bytes.fromhex("1df0")        # retw.n


def test_is_entry_only_for_entry_a1():
    assert is_entry(0x36, 0x41)       # entry a1, imm
    assert not is_entry(0x36, 0x42)   # entry a2 is not used as a function prologue by the toolchain
    assert not is_entry(0x76, 0x01)   # other op0=6 group member (m != 0)


def test_starts_must_be_4_aligned():
    code = bytes.fromhex("00") * 2 + ENTRY + bytes.fromhex("00") * 7 + ENTRY
    assert recover_starts(code, 0x400D0000) == [0x400D000C]   # 2-byte offset candidate rejected


def test_sweep_rejects_entry_shaped_bytes_inside_an_instruction():
    # f1: entry; l32r-like 3-byte insns such that an aligned candidate lands mid-instruction
    body = ENTRY + bytes.fromhex("0c1b" "0c1b")                  # entry, movi.n, movi.n ... (offsets 3,5,7)
    code = body + bytes.fromhex("00") + ENTRY                    # candidate at offset 8
    starts = recover_starts(code, 0x400D0000)
    assert 0x400D0008 in starts
    kept = filter_by_sweep(code, 0x400D0000, starts)
    assert kept[0] == 0x400D0000


def test_function_after_return_is_kept_even_when_sweep_is_desynchronised():
    code = ENTRY + bytes.fromhex("ffffff") + RETWN + bytes.fromhex("0000") + ENTRY + RETWN
    starts = recover_starts(code, 0x400D0000)
    kept = filter_by_sweep(code, 0x400D0000, starts)
    assert kept == starts


@pytest.mark.skipif(not (ROOT / "results" / "functions" / "metrics_functions.json").exists(), reason="no metrics")
def test_recovery_matches_recorded_metrics_on_a_committed_image():
    m = json.loads((ROOT / "results" / "functions" / "metrics_functions.json").read_text())
    name = "m36__O2__full_stack"
    p = ROOT / "dataset" / "out_esp32" / "samples" / name / "firmware.bin"
    if not p.exists():
        pytest.skip("image missing")
    fw = image.load(str(p))
    assert len(recover_functions(fw)) == m["per_sample"][name]["found"]

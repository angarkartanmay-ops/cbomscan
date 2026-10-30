"""The held-out set must not change once frozen (docs/HELDOUT.md). Fails on any added, removed or edited file."""
import hashlib
from pathlib import Path

import pytest

HELD = Path(__file__).resolve().parent.parent / "dataset" / "heldout"
MANIFEST = HELD / "MANIFEST.sha256"


@pytest.mark.skipif(not MANIFEST.exists(), reason="held-out set not frozen yet")
def test_heldout_matches_manifest():
    expected = {}
    for line in MANIFEST.read_text().splitlines():
        h, name = line.split("  ", 1)
        expected[name] = h
    def digests(p):
        raw = p.read_bytes()
        crlf = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        return {hashlib.sha256(raw).hexdigest(), hashlib.sha256(crlf).hexdigest()}

    files = {p.relative_to(HELD).as_posix(): p for p in HELD.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"}
    assert set(files) == set(expected)
    changed = [n for n, p in files.items() if expected[n] not in digests(p)]
    assert not changed, changed

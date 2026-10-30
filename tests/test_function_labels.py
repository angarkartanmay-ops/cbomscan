import gzip
import json
from collections import Counter
from pathlib import Path

import pytest

from cbomscan.taxonomy import SCORED_FAMILIES

ROOT = Path(__file__).resolve().parent.parent
LABELS = ROOT / "dataset" / "functions" / "labels.jsonl.gz"
pytestmark = pytest.mark.skipif(not LABELS.exists(), reason="labels not generated")


def _load():
    with gzip.open(LABELS, "rt", encoding="utf-8") as fh:
        return [json.loads(l) for l in fh]


def test_labels_are_from_the_declared_set():
    allowed = set(SCORED_FAMILIES) | {"support", "other"}
    assert {r["label"] for r in _load()} <= allowed


def test_every_family_label_lies_in_a_truth_code_range():
    """Independent re-derivation for one sample: a family label means the start is inside a truth range."""
    rows = [r for r in _load() if r["sample"] == "m36__O2__full_stack"]
    assert rows
    truth = json.loads((ROOT / "dataset/out_esp32/samples/m36__O2__full_stack/truth.json").read_text())
    for r in rows:
        if r["label"] in SCORED_FAMILIES:
            assert any(x["start"] <= r["start"] < x["end"] and x["kind"] == "code"
                       for x in truth["family_ranges"][r["label"]])
        elif r["label"] == "other":
            assert not any(x["start"] <= r["start"] < x["end"] and x["kind"] == "code"
                           for v in truth["family_ranges"].values() for x in v)


def test_noncrypto_profile_has_no_family_functions_except_linked_by_design():
    c = Counter(r["label"] for r in _load() if r["profile"] == "noncrypto")
    assert sum(v for k, v in c.items() if k in SCORED_FAMILIES) == 0

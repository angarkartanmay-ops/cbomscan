"""The ML tier is optional and off by default; these tests need no trained model."""
import json
import shutil
from pathlib import Path

import pytest

from cbomscan.detect import scan
from cbomscan.image import load

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "dataset" / "out_esp32" / "samples" / "m36__O2__full_stack" / "firmware.bin"


@pytest.mark.skipif(not BIN.exists(), reason="image missing")
def test_default_scan_has_no_ml_evidence():
    res = scan(load(str(BIN)))
    assert not [e for e in res.evidence if e.group == "ml"]


def test_model_with_wrong_sha256_is_refused(tmp_path):
    pytest.importorskip("joblib")
    from cbomscan.ml import load_model
    (tmp_path / "function_classifier.joblib").write_bytes(b"not a model")
    (tmp_path / "function_classifier.json").write_text(json.dumps({"sha256": "0" * 64}))
    with pytest.raises(RuntimeError, match="SHA-256"):
        load_model(tmp_path)


def test_ml_flag_without_a_model_exits_cleanly(tmp_path, capsys, monkeypatch):
    from cbomscan import cli, ml
    monkeypatch.setattr(ml, "MODEL_DIR", tmp_path)       # empty directory: no model
    if not BIN.exists():
        pytest.skip("image missing")
    rc = cli.main(["scan", str(BIN), "-o", str(tmp_path / "out"), "--ml"])
    assert rc == 2 and "phase2_ml.py" in capsys.readouterr().err

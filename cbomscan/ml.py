"""Optional ML tier (Phase II, P2.8): function-level classifier evidence. OFF unless requested (``--ml``).

Pipeline: recover functions (cbomscan.functions) -> per-function features (cbomscan.mlfeatures) -> gradient-boosted
classifier trained on the development set (eval/phase2_ml.py) -> a family counts as detected when at least ``k``
recovered functions are classified as it. The evidence confidence is the family's *development cross-validation
image-level precision* at that k (models/function_classifier.json), a measured number, not a guess.

The model file is a joblib (pickle) artefact produced by this project; it is checked against the SHA-256 recorded in
its metadata before loading. Only load model files you trust: a pickle can execute code.
"""

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from .image import classify_addr

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
RULE = "ml.function_classifier"


def load_model(model_dir=None):
    d = Path(model_dir) if model_dir else MODEL_DIR
    meta = json.loads((d / "function_classifier.json").read_text())
    blob = (d / "function_classifier.joblib").read_bytes()
    if hashlib.sha256(blob).hexdigest() != meta["sha256"]:
        raise RuntimeError("model file does not match the SHA-256 in function_classifier.json; refusing to load")
    import joblib
    import io
    return joblib.load(io.BytesIO(blob)), meta


def classify_functions(fw, model, meta):
    """[(function, predicted class name)] for the recovered functions of ``fw``."""
    from .functions import recover_functions
    from .mlfeatures import image_features
    funcs = recover_functions(fw)
    if not funcs:
        return []
    X, _ = image_features(fw, funcs)
    pred = model.predict(X[:, meta["columns"]])
    return [(f, meta["classes"][p]) for f, p in zip(funcs, pred)]


def ml_evidence(fw, model=None, meta=None):
    from .detect import Evidence
    from .taxonomy import SCORED_FAMILIES
    if model is None:
        model, meta = load_model()
    by = defaultdict(list)
    for f, c in classify_functions(fw, model, meta):
        if c in SCORED_FAMILIES:
            by[c].append(f)
    out = []
    for fam, fs in by.items():
        conf = meta["confidence_by_family"].get(fam)
        if conf is None or len(fs) < meta["k"]:
            continue
        a = fs[0].start
        out.append(Evidence(fam, RULE, "ml", "function-classifier", min(0.99, conf), a, classify_addr(a)[0],
                            f"{len(fs)} recovered functions classified as {fam} (k={meta['k']}); confidence = "
                            f"development cross-validation precision of this family, not calibrated on this image",
                            None, [f.start for f in fs[:8]]))
    return out

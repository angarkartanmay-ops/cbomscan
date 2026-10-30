from pathlib import Path

from cbomscan.api import scan_to_dict

SAMPLE = Path(__file__).resolve().parent.parent / "dataset" / "out" / "samples" / "m36rom__Os__full_stack__sbv2_rsa3072" / "firmware.bin"


def test_scan_to_dict_shape():
    d = scan_to_dict(SAMPLE, "x")
    assert d["chip"] == "ESP32"
    assert len(d["families"]) == 16
    assert d["secureBoot"][0]["crcOk"]
    rsa = next(f for f in d["families"] if f["id"] == "RSA")
    assert rsa["quantumVulnerable"] and rsa["confidence"] >= 0.5 and rsa["evidence"]


def test_upload_endpoint_scans_a_posted_file():
    """POST /api/scan must work on Windows too (a held-open NamedTemporaryFile cannot be reopened there)."""
    import json
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer

    from cbomscan.server import Handler

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/api/scan?name=t",
                                     data=SAMPLE.read_bytes(), method="POST")
        d = json.loads(urllib.request.urlopen(req, timeout=60).read())
    finally:
        srv.shutdown()
        srv.server_close()
    assert d["chip"] == "ESP32" and len(d["families"]) == 16


def test_post_quantum_image_reports_ml_kem():
    path = Path(__file__).resolve().parent.parent / "dataset" / "out_pqc" / "samples" / "pqclean_mlkem768__O2" / "firmware.bin"
    d = scan_to_dict(path, "x")
    kem = next(f for f in d["families"] if f["id"] == "MLKEM")
    assert kem["confidence"] >= 0.5 and not kem["quantumVulnerable"] and kem["risk"] == "none"

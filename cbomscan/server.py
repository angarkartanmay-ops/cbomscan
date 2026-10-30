import json
import tempfile
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from .api import scan_to_dict

ROOT = Path(__file__).resolve().parent.parent
PAGE = Path(__file__).resolve().parent / "dashboard" / "index.html"
SAMPLES = ROOT / "dataset" / "out"
MAX_UPLOAD = 16 * 1024 * 1024


def sample_index():
    index = SAMPLES / "index.json"
    if not index.exists():
        return []
    return json.loads(index.read_text())


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, kind="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            return self.send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if url.path == "/api/samples":
            return self.send(200, sample_index())
        if url.path == "/api/scan":
            name = parse_qs(url.query).get("sample", [""])[0]
            known = {s["sample"] for s in sample_index()}
            if name not in known:
                return self.send(404, {"error": "unknown sample"})
            return self.send(200, scan_to_dict(SAMPLES / "samples" / name / "firmware.bin", name))
        self.send(404, {"error": "not found"})

    def do_POST(self):
        url = urlparse(self.path)
        if url.path != "/api/scan":
            return self.send(404, {"error": "not found"})
        size = int(self.headers.get("Content-Length", 0))
        if size <= 0 or size > MAX_UPLOAD:
            return self.send(413, {"error": "file must be between 1 byte and 16 MB"})
        body = self.rfile.read(size)
        name = parse_qs(url.query).get("name", ["upload.bin"])[0]
        with tempfile.NamedTemporaryFile(suffix=".bin") as tmp:
            tmp.write(body)
            tmp.flush()
            try:
                result = scan_to_dict(tmp.name, name)
            except Exception as err:
                return self.send(422, {"error": f"could not read this file as ESP32 firmware: {err}"})
        self.send(200, result)

    def log_message(self, fmt, *args):
        pass


def serve(host="127.0.0.1", port=8765, open_browser=True):
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"Cryptolens running at {url}  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

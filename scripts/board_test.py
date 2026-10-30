#!/usr/bin/env python3
"""End-to-end test with a real ESP32: read its flash over USB, scan it three ways, and compare.

  python scripts/board_test.py --port COM5          # real board (esptool reads the whole flash)
  python scripts/board_test.py --dump flash.bin     # rehearsal on an existing dump, NOT a board test

Steps: (1) esptool flash-id + read_flash from address 0; (2) scan the dump in-process (cbomscan.api);
(3) scan it through the CLI (writes a CBOM, validated against the CycloneDX 1.6 schema); (4) POST it to the
dashboard server's /api/scan on a temporary local port; (5) check that the in-process and HTTP results are
identical and print what was found. Exit code 0 only if every step succeeds.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def find_port():
    from serial.tools import list_ports
    ports = [p for p in list_ports.comports()]
    if not ports:
        sys.exit("no serial port found: connect the ESP32 over USB (and install its USB-UART driver)")
    for p in ports:
        print(f"  found {p.device}: {p.description} (VID:PID {p.vid and f'{p.vid:04x}'}:{p.pid and f'{p.pid:04x}'})")
    return ports[0].device


def esptool(*args):
    cmd = [sys.executable, "-m", "esptool", *args]
    print("  $", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout[-1500:])
    if r.returncode:
        sys.exit(f"esptool failed:\n{r.stderr[-1500:]}")
    return r.stdout


def read_flash(port, out):
    info = esptool("--port", port, "flash-id")
    m = re.search(r"Detected flash size:\s*(\d+)\s*([MK])B", info)
    size = int(m.group(1)) * (1024 * 1024 if m.group(2) == "M" else 1024) if m else 0x400000
    if not m:
        print("  flash size not detected, assuming 4 MB")
    chip = re.search(r"Chip type:\s*(.+)", info) or re.search(r"Chip is\s*(.+)", info)
    print("  chip:", chip.group(1).strip() if chip else "?", " flash bytes:", size)
    esptool("--port", port, "read-flash", "0", str(size), str(out))
    return chip.group(1).strip() if chip else "?"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port")
    ap.add_argument("--dump", help="use an existing flash dump instead of reading a board (rehearsal)")
    ap.add_argument("--out", default=str(ROOT / "board_out"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    ok = True

    print("[1] flash dump")
    if a.dump:
        dump = Path(a.dump)
        chip = "(rehearsal: no board)"
    else:
        dump = out / "board_flash.bin"
        chip = read_flash(a.port or find_port(), dump)
    print("  dump:", dump, dump.stat().st_size, "bytes  sha256", hashlib.sha256(dump.read_bytes()).hexdigest())

    print("[2] in-process scan (cbomscan.api)")
    from cbomscan.api import scan_to_dict
    local = scan_to_dict(str(dump), "board")
    print(f"  container={local['container']} chip={local['chip']} imageSize={local['imageSize']} "
          f"app={local['app'].get('project_name')} secureBoot={len(local['secureBoot'])} block(s)")

    print("[3] CLI scan + CycloneDX 1.6 validation")
    r = subprocess.run([sys.executable, "-m", "cbomscan", "scan", str(dump), "-o", str(out / "cbom")],
                       capture_output=True, text=True, cwd=ROOT)
    print(r.stdout[-1200:])
    if r.returncode:
        print(r.stderr[-800:])
        ok = False

    print("[4] dashboard server, POST /api/scan")
    from cbomscan.server import Handler
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/api/scan?name=board",
                                 data=dump.read_bytes(), method="POST")
    remote = json.loads(urllib.request.urlopen(req, timeout=120).read())
    srv.shutdown()

    print("[5] compare")
    same = all(local[k] == remote[k] for k in ("sha256", "container", "chip", "imageSize", "families", "keys", "secureBoot"))
    print("  in-process == HTTP result:", same)
    ok &= same
    found = [f for f in remote["families"] if f["confidence"] >= remote["threshold"]]
    print("  families at/above threshold:", ", ".join(f"{f['id']} {f['confidence']:.2f}" for f in found) or "none")
    print("  RESULT:", "OK" if ok else "FAILED", "| chip:", chip)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

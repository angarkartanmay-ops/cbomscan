"""Command-line interface: python -m cbomscan scan firmware.bin -o out/"""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .cbom import build_cbom
from .detect import ALL_GROUPS, DEFAULT_THRESHOLD, scan, present_families
from .taxonomy import FAMILIES, PQC_FAMILIES
from .image import load
from .report import to_html, to_markdown


def cmd_scan(a):
    fw = load(a.firmware)
    groups = a.groups.split(",") if a.groups else ALL_GROUPS
    res = scan(fw, threshold=a.threshold, groups=groups)
    bom = build_cbom(res)
    if not a.no_validate:
        from .validate import validate
        errs = validate(bom)
        if errs:
            print("CBOM failed CycloneDX 1.6 schema validation:", file=sys.stderr)
            for e in errs[:20]:
                print("  " + e, file=sys.stderr)
            return 2
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(a.firmware).stem
    (out / f"{stem}.cbom.json").write_text(json.dumps(bom, indent=2))
    (out / f"{stem}.report.md").write_text(to_markdown(res))
    (out / f"{stem}.report.html").write_text(to_html(res))
    (out / f"{stem}.evidence.json").write_text(json.dumps([e.to_dict() for e in res.evidence], indent=1))
    fams = sorted(present_families(res, families=list(FAMILIES)))
    vuln = [f for f in fams if res.findings.get(f) and res.findings[f].info.quantum_vulnerable]
    print(f"{fw.path}: {fw.container}, {fw.chip}, {len(fw.segments)} segments")
    print(f"  present: {', '.join(fams) or 'none'}")
    print(f"  quantum-vulnerable: {', '.join(vuln) or 'none'}")
    pqc = [f for f in fams if f in PQC_FAMILIES]
    if pqc:
        print(f"  post-quantum (not vulnerable): {', '.join(pqc)}")
    for k in res.keys:
        print(f"  key: {k.describe()}")
    print(f"  wrote {out / (stem + '.cbom.json')} (+ .report.md, .report.html, .evidence.json)")
    return 0


def cmd_info(a):
    fw = load(a.firmware)
    print(f"{fw.path}: {fw.container}, chip {fw.chip}, entry 0x{fw.entry:08x}, image {fw.image_size} bytes")
    for s in fw.segments:
        print(f"  seg {s.index}: {s.region:8s} 0x{s.addr:08x} +{len(s.data):<8d} {s.kind}")
    if fw.app_desc:
        print(f"  app: {fw.app_desc}")
    for b in fw.signature_blocks:
        print(f"  signature block {b.index}: {b.scheme} {b.key_bits}-bit {b.curve or ''} crc_ok={b.crc_ok}")
    for p in fw.partitions:
        print(f"  partition {p['label']}: type {p['type']} sub {p['subtype']} @0x{p['offset']:x} size 0x{p['size']:x}")
    for n in fw.notes:
        print(f"  note: {n}")
    return 0


def cmd_serve(a):
    from .server import serve
    serve(a.host, a.port, not a.no_browser)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cbomscan", description="Find quantum-vulnerable cryptography in ESP32 firmware.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a firmware file and write a CycloneDX CBOM plus reports")
    s.add_argument("firmware")
    s.add_argument("-o", "--out", default="cbom_out")
    s.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    s.add_argument("--groups", default="", help=f"comma list from {','.join(ALL_GROUPS)}")
    s.add_argument("--no-validate", action="store_true")
    s.set_defaults(fn=cmd_scan)
    i = sub.add_parser("info", help="print image structure")
    i.add_argument("firmware")
    i.set_defaults(fn=cmd_info)
    v = sub.add_parser("serve", help="open the Cryptolens dashboard in a browser")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8765)
    v.add_argument("--no-browser", action="store_true")
    v.set_defaults(fn=cmd_serve)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

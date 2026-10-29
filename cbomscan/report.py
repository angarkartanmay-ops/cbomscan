"""Human-readable reports (Markdown and HTML) for a scan."""

import html

from .migration import PRIORITY, PLATFORM_NOTES
from .taxonomy import FAMILIES, PQC_FAMILIES


def _rows(result):
    rows = []
    for f in sorted(result.findings.values(), key=lambda f: (PRIORITY.get(f.family, (9,))[0], -f.confidence)):
        info = f.info
        pri, why = PRIORITY.get(f.family, (5, ""))
        top = f.evidence[0]
        loc = f"0x{top.address:08x} ({top.region})" if top.address is not None else top.region
        rows.append({"family": info.name, "id": f.family, "present": f.present, "confidence": f.confidence,
                     "quantum": "VULNERABLE" if info.quantum_vulnerable else ("post-quantum" if f.family in PQC_FAMILIES else "safe"),
                     "level": "-" if info.nist_quantum_level is None else str(info.nist_quantum_level),
                     "priority": pri, "why": why, "replacement": info.replacement,
                     "params": ", ".join(f.params), "execution": f.execution, "location": loc,
                     "evidence": [f"{e.rule} ({e.confidence:.2f}): {e.detail}" for e in f.evidence]})
    return rows


def to_markdown(result):
    fw = result.firmware
    L = [f"# cbomscan report: {fw.app_desc.get('project_name') or fw.path}", ""]
    L.append(f"- Input: `{fw.path}` ({fw.container}, {len(fw.raw)} bytes, SHA-256 `{fw.sha256[:16]}...`)")
    L.append(f"- Chip: {fw.chip}; entry 0x{fw.entry:08x}; {len(fw.segments)} loaded segments")
    if fw.app_desc:
        L.append(f"- App: {fw.app_desc.get('project_name')} {fw.app_desc.get('version')}, ESP-IDF {fw.app_desc.get('idf_ver')}")
    L.append(f"- Rule groups: {', '.join(result.groups)}; decision threshold {result.threshold}")
    for n in fw.notes:
        L.append(f"- Note: {n}")
    rows = _rows(result)
    present = [r for r in rows if r["present"]]
    vuln = [r for r in present if r["quantum"] == "VULNERABLE"]
    L += ["", "## Summary", ""]
    if vuln:
        L.append(f"**{len(vuln)} quantum-vulnerable public-key famil{'y' if len(vuln) == 1 else 'ies'} found: "
                 f"{', '.join(r['family'] for r in vuln)}.**")
    else:
        L.append("No quantum-vulnerable public-key cryptography detected by Phase I rules.")
    pqc = [r for r in present if r["quantum"] == "post-quantum"]
    if pqc:
        L.append(f"Post-quantum algorithms present (not vulnerable): {', '.join(r['family'] for r in pqc)}.")
    sbk = [k for k in result.keys if k.source == "secure-boot-v2"]
    if sbk:
        L.append(f"Secure Boot V2 root of trust uses **{sbk[0].describe()}**: classical, so a quantum-capable "
                 "attacker who recovers the signing key could sign firmware this device accepts.")
    L += ["", "## Findings (sorted by migration priority)", "",
          "| Priority | Algorithm | Quantum | NIST QL | Confidence | Params | Execution | First evidence | Replace with |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in present:
        L.append(f"| {r['priority']} | {r['family']} | {r['quantum']} | {r['level']} | {r['confidence']:.2f} | "
                 f"{r['params'] or '-'} | {r['execution']} | {r['location']} | {r['replacement']} |")
    weak = [r for r in rows if not r["present"]]
    if weak:
        L += ["", "## Below threshold (weak evidence, not reported as present)", ""]
        for r in weak:
            L.append(f"- {r['family']} ({r['confidence']:.2f}): {r['evidence'][0]}")
    if result.keys:
        L += ["", "## Key material", ""]
        for k in result.keys:
            where = f"0x{k.address:08x} ({k.region})" if k.address is not None else k.region
            L.append(f"- {k.describe()} at {where}; fingerprint {k.fingerprint}")
    L += ["", "## Evidence detail", ""]
    for r in present:
        L.append(f"### {r['family']}")
        L.append(f"Why it matters: {r['why']}")
        for e in r["evidence"]:
            L.append(f"- {e}")
        L.append("")
    L += ["## Platform notes", ""] + [f"- {n}" for n in PLATFORM_NOTES]
    L += ["", "## Known Phase I limits", "",
          "- Rules cannot yet tell ECDSA from ECDH when both share curve code; ECC is reported with the curve.",
          "- AES with run-time generated tables (mbedTLS default) leaves no constants; only hardware use or tables are found.",
          "- Poly1305 masks are often folded into shift instructions by the compiler.",
          "- Presence means the code is linked into the image, not that it runs on a given path."]
    return "\n".join(L) + "\n"


def to_html(result):
    fw = result.firmware
    rows = _rows(result)
    e = html.escape
    title = e(fw.app_desc.get("project_name") or fw.path)
    out = ["<!doctype html>", "<html lang=\"en\">", "<head>", "<meta charset=\"utf-8\">",
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
           f"<title>cbomscan: {title}</title>",
           "<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#1b1b1f;background:#fff}"
           "table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid #d6d6dc;padding:6px 8px;text-align:left;vertical-align:top}"
           "th{background:#f3f3f6}.v{color:#a3201b;font-weight:600}.s{color:#1d6b35}code{font-size:13px}"
           "@media (prefers-color-scheme:dark){body{background:#151518;color:#e8e8ec}th{background:#24242a}th,td{border-color:#3a3a42}.v{color:#ff8a80}.s{color:#7bd88f}}</style>",
           "</head>", "<body>", f"<h1>cbomscan report: {title}</h1>",
           f"<p>{e(fw.container)}, {len(fw.raw)} bytes, chip {e(fw.chip)}, SHA-256 <code>{fw.sha256[:16]}...</code></p>"]
    sbk = [k for k in result.keys if k.source == "secure-boot-v2"]
    if sbk:
        out.append(f"<p class=\"v\">Secure Boot V2 root of trust: {e(sbk[0].describe())}</p>")
    out += ["<table>", "<tr><th>Priority</th><th>Algorithm</th><th>Quantum</th><th>NIST QL</th><th>Confidence</th>"
            "<th>Params</th><th>First evidence</th><th>Replace with</th></tr>"]
    for r in rows:
        if not r["present"]:
            continue
        cls = "v" if r["quantum"] == "VULNERABLE" else "s"  # post-quantum and safe both render as safe
        out.append(f"<tr><td>{r['priority']}</td><td>{e(r['family'])}</td><td class=\"{cls}\">{r['quantum']}</td>"
                   f"<td>{r['level']}</td><td>{r['confidence']:.2f}</td><td>{e(r['params'] or '-')}</td>"
                   f"<td><code>{e(r['location'])}</code></td><td>{e(r['replacement'])}</td></tr>")
    out.append("</table>")
    if result.keys:
        out.append("<h2>Key material</h2><ul>")
        for k in result.keys:
            out.append(f"<li>{e(k.describe())}</li>")
        out.append("</ul>")
    out.append("<h2>Evidence</h2>")
    for r in rows:
        if not r["present"]:
            continue
        out.append(f"<h3>{e(r['family'])}</h3><ul>")
        for ev in r["evidence"]:
            out.append(f"<li>{e(ev)}</li>")
        out.append("</ul>")
    out += ["</body>", "</html>"]
    return "\n".join(out) + "\n"

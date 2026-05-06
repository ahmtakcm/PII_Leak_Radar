import html
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from core.reporting import build_report


def write_manual_import_json(
    events: List[Dict[str, Any]],
    output_path: Path,
    scanned_files: List[str] = None,
    errors: List[str] = None,
):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(
        "manual_import",
        summary={
            "event_count": len(events),
            "scanned_file_count": len(scanned_files or []),
        },
        errors=errors or [],
        inputs={"scanned_files": scanned_files or []},
        outputs={"json": str(output_path)},
        data={"legacy_events": events},
        raw_sensitive_output=False,
    )
    payload = {
        "report_schema": report,
        "events": events,
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path


def write_manual_import_html(events: List[Dict[str, Any]], scanned_files: List[str], output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    file_rows = "".join(f"<li>{html.escape(str(f))}</li>" for f in scanned_files)

    rows = []
    for e in events:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(e.get('source_id', '')))}</td>"
            f"<td><span class='risk {html.escape(str(e.get('risk_label', '')))}'>{html.escape(str(e.get('risk_label', '')))}</span></td>"
            f"<td>{html.escape(str(e.get('risk_score', '')))}</td>"
            f"<td>{html.escape(str(e.get('category', '')))}</td>"
            f"<td>{html.escape(str(e.get('title', '')))}</td>"
            f"<td>{html.escape(str(e.get('url', '')))}</td>"
            f"<td>{html.escape(str(e.get('legal_level', '')))}</td>"
            f"<td>{html.escape(str(e.get('evidence_ref', '')))}</td>"
            f"<td>{html.escape(str(e.get('masked_snippet', '')))}</td>"
            f"<td>{html.escape(str(e.get('recommended_action', '')))}</td>"
            "</tr>"
        )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    content = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>PII Leak Radar - Manual Import Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 24px;
    background: #111827;
    color: #e5e7eb;
}}
.card {{
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 18px;
}}
.table-wrap {{
    overflow-x: auto;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background: #0f172a;
}}
th, td {{
    border-bottom: 1px solid #374151;
    padding: 8px;
    text-align: left;
    vertical-align: top;
    font-size: 13px;
}}
th {{
    background: #111827;
    color: #93c5fd;
    white-space: nowrap;
}}
.risk {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    background: #374151;
    font-weight: 700;
    white-space: nowrap;
}}
.risk.critical {{ background: #7f1d1d; color: #fecaca; }}
.risk.high {{ background: #78350f; color: #fde68a; }}
.risk.medium {{ background: #1e3a8a; color: #bfdbfe; }}
.risk.low {{ background: #064e3b; color: #bbf7d0; }}
.note {{
    color: #fbbf24;
}}
</style>
</head>
<body>
<div class="card">
<h1>PII Leak Radar - Manual Source Import Report</h1>
<p>Üretim zamanı: {html.escape(generated)}</p>
<p>Bulgu sayısı: <b>{len(events)}</b></p>
<p class="note">Yasal not: Bu rapor kullanıcı tarafından sağlanan veya açık/izinli kaynaklardan elde edilen manuel kayıtları işler. Yetkisiz erişim, credential deneme, exploit/bypass veya illegal market/grup işlemi içermez.</p>
</div>

<div class="card">
<h2>Taranan Dosyalar</h2>
<ul>
{file_rows if file_rows else '<li>Dosya yok.</li>'}
</ul>
</div>

<div class="card">
<h2>Manuel Import Bulguları</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>Source</th>
<th>Risk</th>
<th>Score</th>
<th>Category</th>
<th>Title</th>
<th>URL</th>
<th>Legal Level</th>
<th>Evidence Ref</th>
<th>Masked Snippet</th>
<th>Önerilen Aksiyon</th>
</tr>
</thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="10">Bulgu yok.</td></tr>'}
</tbody>
</table>
</div>
</div>
</body>
</html>
"""
    output_path.write_text(content, encoding="utf-8")
    return output_path

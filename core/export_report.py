import html
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from core.reporting import build_report


def write_export_report(
    hits: List[Dict[str, Any]],
    scanned_files: List[str],
    output_path: str = "reports/export_parse_report.html",
):
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for h in hits:
        indicator_types = ", ".join(h.get("indicator_types", []))
        snippet = h.get("masked_snippet", "")

        rows.append(
            "<tr>"
            f"<td>{html.escape(str(h.get('risk_label', '')))}</td>"
            f"<td>{html.escape(str(h.get('risk_score', '')))}</td>"
            f"<td>{html.escape(str(h.get('platform', '')))}</td>"
            f"<td>{html.escape(str(h.get('source_file_name', '')))}</td>"
            f"<td>{html.escape(str(h.get('timestamp', '')))}</td>"
            f"<td>{html.escape(str(h.get('author', '')))}</td>"
            f"<td>{html.escape(indicator_types)}</td>"
            f"<td>{html.escape(snippet)}</td>"
            f"<td>{html.escape(str(h.get('recommended_action', '')))}</td>"
            "</tr>"
        )

    file_rows = []
    for f in scanned_files:
        file_rows.append(f"<li>{html.escape(f)}</li>")

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    content = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>PII Leak Radar - Export Parse Report</title>
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
.badge {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    background: #374151;
    font-weight: 700;
}}
.note {{
    color: #fbbf24;
}}
</style>
</head>
<body>
<div class="card">
<h1>PII Leak Radar - Telegram/Discord Export Parse Report</h1>
<p><span class="badge">offline parser</span> <span class="badge">user-provided export only</span> <span class="badge">masked output</span></p>
<p>Üretim zamanı: {html.escape(generated)}</p>
<p>Bulgu sayısı: <b>{len(hits)}</b></p>
<p class="note">Yasal not: Bu modül yalnızca kullanıcı tarafından sağlanan export dosyalarını offline analiz eder. Kapalı gruba erişim, bot kullanımı, credential deneme veya illegal market işlemi yapmaz.</p>
</div>

<div class="card">
<h2>Taranan Dosyalar</h2>
<ul>
{''.join(file_rows) if file_rows else '<li>Dosya bulunamadı.</li>'}
</ul>
</div>

<div class="card">
<h2>Bulgu Tablosu</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>Risk</th>
<th>Score</th>
<th>Platform</th>
<th>File</th>
<th>Time</th>
<th>Author</th>
<th>Indicator Types</th>
<th>Masked Snippet</th>
<th>Önerilen Aksiyon</th>
</tr>
</thead>
<tbody>
{''.join(rows) if rows else '<tr><td colspan="9">Bulgu yok.</td></tr>'}
</tbody>
</table>
</div>
</div>
</body>
</html>
"""
    out.write_text(content, encoding="utf-8")
    return out


def write_export_json(
    hits: List[Dict[str, Any]],
    output_path: str = "reports/export_parse_results.json",
    scanned_files: List[str] = None,
    errors: List[str] = None,
):
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(
        "export_parse",
        summary={
            "hit_count": len(hits),
            "scanned_file_count": len(scanned_files or []),
        },
        errors=errors or [],
        inputs={"scanned_files": scanned_files or []},
        outputs={"json": str(out)},
        data={"legacy_hits": hits},
        raw_sensitive_output=False,
    )
    payload = {
        "report_schema": report,
        "hits": hits,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

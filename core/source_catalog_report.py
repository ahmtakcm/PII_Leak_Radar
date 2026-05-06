import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any


def write_catalog_json(rows: List[Dict[str, Any]], output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path


def write_catalog_html(rows: List[Dict[str, Any]], output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    status_counts = Counter(str(r.get("status", "")) for r in rows)
    category_counts = Counter(str(r.get("category", "")) for r in rows)

    metric_html = "".join(
        f"<div class='metric'><div class='label'>{html.escape(k)}</div><div class='value'>{v}</div></div>"
        for k, v in status_counts.items()
    )

    category_html = "".join(
        f"<li><b>{html.escape(k)}</b>: {v}</li>"
        for k, v in category_counts.items()
    )

    row_html = []
    for r in rows:
        row_html.append(
            "<tr>"
            f"<td>{html.escape(str(r.get('id', '')))}</td>"
            f"<td>{html.escape(str(r.get('name', '')))}</td>"
            f"<td><span class='status {html.escape(str(r.get('status', '')))}'>{html.escape(str(r.get('status', '')))}</span></td>"
            f"<td>{html.escape(str(r.get('enabled', '')))}</td>"
            f"<td>{html.escape(str(r.get('category', '')))}</td>"
            f"<td>{html.escape(str(r.get('adapter', '')))}</td>"
            f"<td>{html.escape(str(r.get('legal_level', '')))}</td>"
            f"<td>{html.escape(str(r.get('review_priority', '')))}</td>"
            f"<td>{html.escape(str(r.get('risk_base', '')))}</td>"
            f"<td>{html.escape(str(r.get('blocker', '')))}</td>"
            f"<td>{html.escape(str(r.get('recommended_next_step', '')))}</td>"
            "</tr>"
        )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    content = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>PII Leak Radar - Source Catalog</title>
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
.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 18px;
}}
.metric {{
    background: #0f172a;
    border: 1px solid #374151;
    border-radius: 14px;
    padding: 14px;
}}
.metric .label {{
    color: #9ca3af;
    font-size: 13px;
}}
.metric .value {{
    font-size: 28px;
    font-weight: 800;
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
.status {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    background: #374151;
    font-weight: 700;
    white-space: nowrap;
}}
.status.active {{ background: #064e3b; color: #bbf7d0; }}
.status.catalog_only {{ background: #374151; color: #e5e7eb; }}
.status.placeholder {{ background: #1e3a8a; color: #bfdbfe; }}
.status.scope_required {{ background: #78350f; color: #fde68a; }}
.status.legal_review_required {{ background: #7f1d1d; color: #fecaca; }}
.status.needs_adapter {{ background: #581c87; color: #e9d5ff; }}
.note {{
    color: #fbbf24;
}}
</style>
</head>
<body>
<div class="card">
<h1>PII Leak Radar - Source Catalog</h1>
<p>Üretim zamanı: {html.escape(generated)}</p>
<p class="note">Yasal not: Bu katalog kaynak tiplerini sınıflandırır. Yüksek riskli kaynaklarda aktif katılım, yetkisiz erişim, davet satın alma/kullanma, credential deneme veya exploit/bypass işlemi yapılmaz.</p>
</div>

<div class="grid">
<div class="metric"><div class="label">Toplam Kaynak</div><div class="value">{len(rows)}</div></div>
{metric_html}
</div>

<div class="card">
<h2>Kategori Özeti</h2>
<ul>
{category_html}
</ul>
</div>

<div class="card">
<h2>Kaynak Envanteri</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>Status</th>
<th>Enabled</th>
<th>Category</th>
<th>Adapter</th>
<th>Legal Level</th>
<th>Review Priority</th>
<th>Risk Base</th>
<th>Blocker</th>
<th>Recommended Next Step</th>
</tr>
</thead>
<tbody>
{''.join(row_html)}
</tbody>
</table>
</div>
</div>
</body>
</html>
"""
    output_path.write_text(content, encoding="utf-8")
    return output_path

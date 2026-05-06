import html
from collections import Counter
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any


def write_dashboard(
    events: List[Dict[str, Any]],
    output_path: str = "reports/dashboard.html",
    source_runs: List[Dict[str, Any]] = None,
):
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    source_runs = source_runs or []
    stats = _build_stats(events, source_runs)
    ops = _load_operational_status(out.parent)
    retention = _load_retention_status(out.parent.parent)

    source_rows = []
    for r in source_runs:
        source_rows.append(
            "<tr>"
            f"<td>{html.escape(str(r.get('source_id', '')))}</td>"
            f"<td><span class='status {html.escape(str(r.get('status', '')))}'>{html.escape(str(r.get('status', '')))}</span></td>"
            f"<td>{html.escape(str(r.get('fetched_count', '')))}</td>"
            f"<td>{html.escape(str(r.get('new_count', '')))}</td>"
            f"<td>{html.escape(str(r.get('duplicate_count', '')))}</td>"
            f"<td>{html.escape(str(r.get('checked_at', '')))}</td>"
            f"<td>{html.escape(str(r.get('duration_ms', '')))}</td>"
            f"<td>{html.escape(str(r.get('suggested_action', '')))}</td>"
            f"<td>{html.escape(str(r.get('error_message', '')))}</td>"
            "</tr>"
        )

    event_rows = []
    for e in events:
        event_rows.append(
            "<tr>"
            f"<td>{html.escape(str(e.get('source_id', '')))}</td>"
            f"<td><span class='risk {html.escape(str(e.get('risk_label', '')))}'>{html.escape(str(e.get('risk_label', '')))}</span></td>"
            f"<td>{html.escape(str(e.get('risk_score', '')))}</td>"
            f"<td>{html.escape(str(e.get('type', '')))}</td>"
            f"<td>{html.escape(str(e.get('title', '')))}</td>"
            f"<td>{html.escape(str(e.get('external_id', '')))}</td>"
            f"<td>{html.escape(str(e.get('legal_level', '')))}</td>"
            f"<td>{html.escape(str(e.get('recommended_action', '')))}</td>"
            f"<td>{html.escape(str(e.get('seen_count', '')))}</td>"
            f"<td>{html.escape(str(e.get('last_seen', '')))}</td>"
            "</tr>"
        )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    content = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>PII Leak Radar - Unified Dashboard</title>
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
h1, h2 {{ margin-top: 0; }}
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
    margin-top: 6px;
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
td {{
    min-width: 90px;
}}
.badge, .risk, .status {{
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
.status.ok {{ background: #064e3b; color: #bbf7d0; }}
.status.error {{ background: #7f1d1d; color: #fecaca; }}
.status.skipped {{ background: #374151; color: #e5e7eb; }}
.note {{
    color: #fbbf24;
}}
.small {{
    color: #9ca3af;
    font-size: 13px;
}}
</style>
</head>
<body>
<div class="card">
<h1>PII Leak Radar - Unified Dashboard</h1>
<p>
<span class="badge">source registry</span>
<span class="badge">export parser</span>
<span class="badge">dry-run</span>
<span class="badge">alerts disabled</span>
<span class="badge">sanitized logging</span>
</p>
<p>Üretim zamanı: {html.escape(generated)}</p>
<p class="note">Yasal not: Bu dashboard savunma/OSINT/adli bilişim amaçlıdır. Yetkisiz erişim, credential kullanımı, exploit/bypass veya illegal market/grup işlemi yapılmaz.</p>
</div>

<div class="grid">
<div class="metric"><div class="label">Toplam Gözlem</div><div class="value">{stats['total_events']}</div></div>
<div class="metric"><div class="label">Critical</div><div class="value">{stats['critical']}</div></div>
<div class="metric"><div class="label">High</div><div class="value">{stats['high']}</div></div>
<div class="metric"><div class="label">Medium</div><div class="value">{stats['medium']}</div></div>
<div class="metric"><div class="label">Low</div><div class="value">{stats['low']}</div></div>
<div class="metric"><div class="label">Kaynak Sayısı</div><div class="value">{stats['source_count']}</div></div>
<div class="metric"><div class="label">Policy Gate</div><div class="value">{html.escape(ops['policy_status'])}</div></div>
<div class="metric"><div class="label">Connector Readiness</div><div class="value">{html.escape(ops['connector_status'])}</div></div>
<div class="metric"><div class="label">Fixture Gate</div><div class="value">{html.escape(ops['fixture_status'])}</div></div>
<div class="metric"><div class="label">Fixture Errors</div><div class="value">{html.escape(str(ops['fixture_errors']))}</div></div>
<div class="metric"><div class="label">Network Feeds</div><div class="value">{html.escape(ops['network_feeds'])}</div></div>
<div class="metric"><div class="label">Connector Warnings</div><div class="value">{html.escape(str(ops['connector_warnings']))}</div></div>
<div class="metric"><div class="label">Release Workflow</div><div class="value">{html.escape(ops['release_workflow'])}</div></div>
<div class="metric"><div class="label">Release Notes</div><div class="value">{html.escape(ops['release_notes'])}</div></div>
<div class="metric"><div class="label">DB Observations</div><div class="value">{html.escape(str(retention['observation_count']))}</div></div>
<div class="metric"><div class="label">DB Source Runs</div><div class="value">{html.escape(str(retention['source_run_count']))}</div></div>
<div class="metric"><div class="label">Last Observation</div><div class="value">{html.escape(str(retention['last_observation']))}</div></div>
<div class="metric"><div class="label">Retention Hint</div><div class="value">{html.escape(str(retention['retention_hint']))}</div></div>
</div>

<div class="card">
<h2>Kaynak Durumu</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>Source</th>
<th>Status</th>
<th>Fetched</th>
<th>New</th>
<th>Duplicate</th>
<th>Last Check</th>
<th>ms</th>
<th>Önerilen Aksiyon</th>
<th>Hata</th>
</tr>
</thead>
<tbody>
{''.join(source_rows) if source_rows else '<tr><td colspan="9">Henüz kaynak durumu yok.</td></tr>'}
</tbody>
</table>
</div>
<p class="small">Not: Duplicate yüksekse bu her zaman hata değildir; ikinci ve sonraki taramalarda beklenen davranıştır.</p>
</div>

<div class="card">
<h2>Son Gözlemler</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>Source</th>
<th>Risk</th>
<th>Score</th>
<th>Type</th>
<th>Title</th>
<th>External ID</th>
<th>Legal Level</th>
<th>Önerilen Aksiyon</th>
<th>Seen</th>
<th>Last Seen</th>
</tr>
</thead>
<tbody>
{''.join(event_rows) if event_rows else '<tr><td colspan="10">Henüz kayıt yok.</td></tr>'}
</tbody>
</table>
</div>
</div>
</body>
</html>
"""
    out.write_text(content, encoding="utf-8")
    return out


def _build_stats(events: List[Dict[str, Any]], source_runs: List[Dict[str, Any]]):
    risk_counts = Counter(str(e.get("risk_label", "unknown")).lower() for e in events)
    sources = set()

    for e in events:
        if e.get("source_id"):
            sources.add(str(e.get("source_id")))

    for r in source_runs:
        if r.get("source_id"):
            sources.add(str(r.get("source_id")))

    return {
        "total_events": len(events),
        "critical": risk_counts.get("critical", 0),
        "high": risk_counts.get("high", 0),
        "medium": risk_counts.get("medium", 0),
        "low": risk_counts.get("low", 0),
        "source_count": len(sources),
    }


def _load_json(path: Path):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return {}
    return {}


def _load_operational_status(report_dir: Path):
    policy = _load_json(report_dir / "source_registry_policy_validate_report.json")
    connectors = _load_json(report_dir / "safe_connectors_dry_run_results.json")
    fixtures = _load_json(report_dir / "connector_fixture_validate_report.json")
    release_notes = _load_json(report_dir / "release_notes.json")
    pipeline = _load_json(report_dir / "full_pipeline_report.json")

    connector_summary = connectors.get("summary", {})
    if not isinstance(connector_summary, dict):
        connector_summary = {}

    network = "off"
    if pipeline.get("network_feeds_enabled") is True:
        network = "on"

    fixture_summary = fixtures.get("summary", {})
    if not isinstance(fixture_summary, dict):
        fixture_summary = {}

    release_summary = release_notes.get("summary", {})
    if not isinstance(release_summary, dict):
        release_summary = {}

    return {
        "policy_status": str(policy.get("status", "unknown")),
        "connector_status": str(connectors.get("status", connector_summary.get("status", "unknown"))),
        "connector_warnings": connector_summary.get("warning_count", connectors.get("warning_count", 0)),
        "fixture_status": str(fixtures.get("status", "unknown")),
        "fixture_errors": fixture_summary.get("error_count", "unknown"),
        "network_feeds": network,
        "release_workflow": "ready" if (report_dir.parent / ".github" / "workflows" / "release.yml").exists() else "missing",
        "release_notes": str(release_summary.get("commit_count", "unknown")),
    }


def _load_retention_status(project_root: Path):
    db_path = project_root / "data" / "pii_radar.db"
    result = {
        "observation_count": "unknown",
        "source_run_count": "unknown",
        "last_observation": "unknown",
        "retention_hint": "check",
    }

    if not db_path.exists():
        result["retention_hint"] = "no-db"
        return result

    try:
        conn = sqlite3.connect(str(db_path))
        observation_count = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        source_run_count = conn.execute("SELECT COUNT(*) FROM source_runs").fetchone()[0]
        last_seen = conn.execute("SELECT MAX(last_seen) FROM observations").fetchone()[0]
        conn.close()
    except Exception:
        result["retention_hint"] = "db-error"
        return result

    result["observation_count"] = observation_count
    result["source_run_count"] = source_run_count
    result["last_observation"] = "recent" if last_seen else "none"
    result["retention_hint"] = "cleanup" if int(source_run_count) >= 10000 else "ok"
    return result

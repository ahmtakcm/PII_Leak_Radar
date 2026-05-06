import html
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from core.reporting import build_report


ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"


BASE_STEPS = [
    {
        "id": "source_policy_validate",
        "title": "Source Registry Policy Validation",
        "command": [sys.executable, str(ROOT / "run_source_registry_policy_validate.py")],
    },
    {
        "id": "safe_connectors",
        "title": "Safe Connectors Dry-Run",
        "command": [sys.executable, str(ROOT / "run_safe_connectors_dry_run.py")],
    },
    {
        "id": "export_parser",
        "title": "Telegram/Discord Export Parser",
        "command": [sys.executable, str(ROOT / "run_export_parse.py")],
    },
    {
        "id": "manual_import",
        "title": "Manual Source Import",
        "command": [sys.executable, str(ROOT / "run_manual_import.py")],
    },
    {
        "id": "source_catalog",
        "title": "Source Catalog Review",
        "command": [sys.executable, str(ROOT / "run_source_catalog_review.py")],
    },
    {
        "id": "dashboard_refresh",
        "title": "Unified Dashboard Refresh",
        "command": [sys.executable, str(ROOT / "run_dashboard_refresh.py")],
    },
]


NETWORK_STEP = {
    "id": "source_registry",
    "title": "Source Registry Live Public Feed Scan",
    "command": [sys.executable, str(ROOT / "run_registry_dry_scan.py"), "--with-network"],
}


def parse_args():
    parser = argparse.ArgumentParser(description="PII Leak Radar full pipeline")
    parser.add_argument(
        "--with-network-feeds",
        action="store_true",
        help="Include live public feed fetches. Default pipeline is offline-safe.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    REPORTS.mkdir(parents=True, exist_ok=True)

    print("=== PII Leak Radar | Full Pipeline ===")
    print(f"project={ROOT}")
    print(f"mode=dry-run alerts-disabled sanitized network_feeds={args.with_network_feeds}")
    print("")

    started_all = time.perf_counter()
    results = []
    steps = build_steps(args.with_network_feeds)

    for step in steps:
        result = run_step(step)
        results.append(result)

        if result["status"] != "ok":
            print("")
            print(f"[WARN] {step['id']} adımı hata verdi. Pipeline devam etti ama raporu kontrol et.")
            print("")

    duration_ms = int((time.perf_counter() - started_all) * 1000)

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "project": str(ROOT),
        "duration_ms": duration_ms,
        "network_feeds_enabled": bool(args.with_network_feeds),
        "status": "ok" if all(r["status"] == "ok" for r in results) else "warning",
        "steps": results,
        "reports": {
            "dashboard": str(REPORTS / "dashboard.html"),
            "source_registry_policy_validate": str(REPORTS / "source_registry_policy_validate_report.html"),
            "safe_connectors_dry_run": str(REPORTS / "safe_connectors_dry_run_report.html"),
            "source_catalog": str(REPORTS / "source_catalog.html"),
            "export_parse": str(REPORTS / "export_parse_report.html"),
            "manual_import": str(REPORTS / "manual_import_report.html"),
            "full_pipeline": str(REPORTS / "full_pipeline_report.html"),
        },
    }
    summary["report_schema"] = build_report(
        "full_pipeline",
        summary={
            "duration_ms": duration_ms,
            "step_count": len(results),
            "network_feeds_enabled": bool(args.with_network_feeds),
            "status": summary["status"],
        },
        warnings=[r for r in results if r.get("status") == "warning"],
        errors=[r for r in results if r.get("status") in {"error", "timeout"}],
        inputs={"network_feeds_enabled": bool(args.with_network_feeds)},
        outputs={
            "json": str(REPORTS / "full_pipeline_report.json"),
            "html": str(REPORTS / "full_pipeline_report.html"),
            "dashboard": str(REPORTS / "dashboard.html"),
        },
        data={"step_ids": [r.get("id") for r in results]},
        raw_sensitive_output=False,
    )

    json_path = REPORTS / "full_pipeline_report.json"
    html_path = REPORTS / "full_pipeline_report.html"

    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    write_html(summary, html_path)

    print("")
    print("=== FULL PIPELINE ÖZET ===")
    print(f"Durum: {summary['status']}")
    print(f"Süre: {duration_ms} ms")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    print(f"Dashboard: {REPORTS / 'dashboard.html'}")
    print("")
    print("Not: Full pipeline dry-run/savunma modunda çalışır; alarm kapalıdır.")


def build_steps(with_network_feeds=False):
    steps = list(BASE_STEPS)
    if with_network_feeds:
        steps.insert(2, NETWORK_STEP)
    return steps


def run_step(step):
    print(f"[RUN] {step['id']} | {step['title']}")
    started = time.perf_counter()

    try:
        proc = subprocess.run(
            step["command"],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            timeout=180,
        )

        duration_ms = int((time.perf_counter() - started) * 1000)
        status = classify_step_status(proc.returncode, proc.stdout, proc.stderr)

        print(proc.stdout.strip())

        if proc.stderr.strip():
            print("[STDERR]")
            print(proc.stderr.strip())

        print(f"[{status.upper()}] {step['id']} | returncode={proc.returncode} | {duration_ms} ms")
        print("")

        return {
            "id": step["id"],
            "title": step["title"],
            "status": status,
            "returncode": proc.returncode,
            "duration_ms": duration_ms,
            "stdout_tail": tail(proc.stdout),
            "stderr_tail": tail(proc.stderr),
        }

    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        print(f"[ERROR] {step['id']} timeout | {duration_ms} ms")
        print("")

        return {
            "id": step["id"],
            "title": step["title"],
            "status": "timeout",
            "returncode": None,
            "duration_ms": duration_ms,
            "stdout_tail": tail(exc.stdout or ""),
            "stderr_tail": tail(exc.stderr or ""),
        }

    except Exception as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        print(f"[ERROR] {step['id']} {type(exc).__name__}: {exc}")
        print("")

        return {
            "id": step["id"],
            "title": step["title"],
            "status": "error",
            "returncode": None,
            "duration_ms": duration_ms,
            "stdout_tail": "",
            "stderr_tail": f"{type(exc).__name__}: {exc}",
        }


def tail(text, max_lines=25):
    lines = str(text or "").splitlines()
    return "\n".join(lines[-max_lines:])


def classify_step_status(returncode, stdout, stderr):
    if returncode != 0:
        return "error"

    combined = f"{stdout or ''}\n{stderr or ''}"
    warning_markers = [
        "[ERROR]",
        "status=fail",
        "SOURCE_REGISTRY_POLICY_VALIDATE\nstatus=fail",
    ]
    if any(marker in combined for marker in warning_markers):
        return "warning"

    for line in combined.splitlines():
        text = line.strip().lower()
        if text.startswith("hata:"):
            try:
                if int(text.split(":", 1)[1].strip()) > 0:
                    return "warning"
            except ValueError:
                return "warning"
        if text.startswith("error_count="):
            try:
                if int(text.split("=", 1)[1].strip()) > 0:
                    return "warning"
            except ValueError:
                return "warning"

    return "ok"


def write_html(summary, path):
    rows = []

    for step in summary["steps"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(step.get('id', '')))}</td>"
            f"<td>{html.escape(str(step.get('title', '')))}</td>"
            f"<td><span class='status {html.escape(str(step.get('status', '')))}'>{html.escape(str(step.get('status', '')))}</span></td>"
            f"<td>{html.escape(str(step.get('returncode', '')))}</td>"
            f"<td>{html.escape(str(step.get('duration_ms', '')))}</td>"
            f"<td><pre>{html.escape(str(step.get('stdout_tail', '')))}</pre></td>"
            f"<td><pre>{html.escape(str(step.get('stderr_tail', '')))}</pre></td>"
            "</tr>"
        )

    report_links = []
    for name, target in summary.get("reports", {}).items():
        rel = Path(target).name
        report_links.append(f"<li><a href='{html.escape(rel)}'>{html.escape(name)}</a></li>")

    content = f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>PII Leak Radar - Full Pipeline Report</title>
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
.status {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 999px;
    background: #374151;
    font-weight: 700;
}}
.status.ok {{ background: #064e3b; color: #bbf7d0; }}
.status.warning {{ background: #78350f; color: #fde68a; }}
.status.error, .status.timeout {{ background: #7f1d1d; color: #fecaca; }}
pre {{
    white-space: pre-wrap;
    max-width: 520px;
    max-height: 260px;
    overflow: auto;
    background: #111827;
    border: 1px solid #374151;
    padding: 8px;
    border-radius: 10px;
}}
a {{
    color: #93c5fd;
}}
.note {{
    color: #fbbf24;
}}
</style>
</head>
<body>
<div class="card">
<h1>PII Leak Radar - Full Pipeline Report</h1>
<p><b>Durum:</b> {html.escape(str(summary.get('status', '')))}</p>
<p><b>Üretim zamanı:</b> {html.escape(str(summary.get('generated_at', '')))}</p>
<p><b>Süre:</b> {html.escape(str(summary.get('duration_ms', '')))} ms</p>
<p class="note">Yasal not: Bu pipeline savunma/OSINT/adli bilişim amaçlıdır. Yetkisiz erişim, credential kullanımı, exploit/bypass veya illegal market/grup işlemi yapmaz.</p>
</div>

<div class="card">
<h2>Rapor Linkleri</h2>
<ul>
{''.join(report_links)}
</ul>
</div>

<div class="card">
<h2>Adım Durumları</h2>
<div class="table-wrap">
<table>
<thead>
<tr>
<th>ID</th>
<th>Başlık</th>
<th>Durum</th>
<th>Return Code</th>
<th>Süre ms</th>
<th>Stdout Tail</th>
<th>Stderr Tail</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</div>
</div>
</body>
</html>
"""

    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()

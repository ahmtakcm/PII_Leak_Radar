import html
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REPORTS = ROOT / "reports"
DASHBOARD = REPORTS / "dashboard.html"
ASSET_REPORT = REPORTS / "asset_match_report.json"
SCOPE_REPORT = REPORTS / "asset_scope_validate_report.json"

START = "<!-- PII_LEAK_RADAR_ASSET_MATCH_CARD_START -->"
END = "<!-- PII_LEAK_RADAR_ASSET_MATCH_CARD_END -->"

def safe_load_json(path):
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), None
    except Exception as exc:
        return None, "json_error: " + str(exc)

def esc(value):
    return html.escape(str(value))

def scope_summary():
    data, error = safe_load_json(SCOPE_REPORT)
    if error:
        return {
            "status": "skipped",
            "active_registry_mode": "unknown",
            "local_asset_count": 0,
            "active_asset_count": 0,
            "active_match_value_count": 0,
            "warning_count": 0,
            "error_count": 0,
        }

    validation = data.get("local_validation", {}) if isinstance(data, dict) else {}
    return {
        "status": data.get("status", "unknown"),
        "active_registry_mode": data.get("active_registry_mode", "unknown"),
        "local_asset_count": data.get("local_asset_count", 0),
        "active_asset_count": data.get("active_asset_count", 0),
        "active_match_value_count": data.get("active_match_value_count", 0),
        "warning_count": len(validation.get("warnings", [])),
        "error_count": len(validation.get("errors", [])),
    }

def build_card(data, error=None):
    scope = scope_summary()

    if error:
        status = "skipped"
        record_count = 0
        match_count = 0
        asset_count = 0
        max_risk = 0
        by_label = {}
        note = error
    else:
        status = data.get("status", "unknown")
        summary = data.get("summary", {})
        record_count = summary.get("record_count", 0)
        match_count = summary.get("match_count", 0)
        asset_count = summary.get("asset_count", 0)
        max_risk = summary.get("max_risk_score", 0)
        by_label = data.get("by_label", {})
        if int(match_count or 0) == 0:
            note = "No asset matches found. This is expected while assets.local.json is empty or sample assets do not match current records."
        else:
            note = "Asset matches found. Review masked snippets in asset_match_report.html."

    label_rows = []
    for label, item in by_label.items():
        s = item.get("summary", {})
        label_rows.append(
            "<tr>"
            + "<td>" + esc(label) + "</td>"
            + "<td>" + esc(item.get("status")) + "</td>"
            + "<td>" + esc(s.get("record_count", 0)) + "</td>"
            + "<td>" + esc(s.get("match_count", 0)) + "</td>"
            + "<td>" + esc(s.get("max_risk_score", 0)) + "</td>"
            + "</tr>"
        )

    if not label_rows:
        label_rows.append("<tr><td colspan='5'>No source label summary available.</td></tr>")

    generated = datetime.now().isoformat(timespec="seconds")

    return START + """
<section id="asset-match-card" style="margin:24px 0;padding:18px;border:1px solid #d7dde8;border-radius:14px;background:#f8fafc;font-family:Arial, sans-serif;">
  <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;">
    <div>
      <h2 style="margin:0 0 6px 0;">Asset Match Summary</h2>
      <p style="margin:0;color:#475569;">Sprint 2.1/2.3 offline asset match and registry summary. Alerts remain disabled.</p>
    </div>
    <div style="font-size:12px;color:#64748b;">Generated: """ + esc(generated) + """</div>
  </div>

  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:16px;">
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Registry Mode</b><br>""" + esc(scope.get("active_registry_mode")) + """</div>
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Active Assets</b><br>""" + esc(scope.get("active_asset_count")) + """</div>
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Match Values</b><br>""" + esc(scope.get("active_match_value_count")) + """</div>
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Local Assets</b><br>""" + esc(scope.get("local_asset_count")) + """</div>
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Validator</b><br>""" + esc(scope.get("status")) + """</div>
  </div>

  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:10px;">
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Report Status</b><br>""" + esc(status) + """</div>
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Records</b><br>""" + esc(record_count) + """</div>
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Matches</b><br>""" + esc(match_count) + """</div>
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Matched Assets</b><br>""" + esc(asset_count) + """</div>
    <div style="padding:12px;background:white;border-radius:10px;border:1px solid #e2e8f0;"><b>Max Risk</b><br>""" + esc(max_risk) + """</div>
  </div>

  <p style="margin:14px 0;color:#334155;">""" + esc(note) + """</p>

  <table style="border-collapse:collapse;width:100%;background:white;">
    <thead>
      <tr>
        <th style="border:1px solid #e2e8f0;padding:8px;text-align:left;">Source</th>
        <th style="border:1px solid #e2e8f0;padding:8px;text-align:left;">Status</th>
        <th style="border:1px solid #e2e8f0;padding:8px;text-align:left;">Records</th>
        <th style="border:1px solid #e2e8f0;padding:8px;text-align:left;">Matches</th>
        <th style="border:1px solid #e2e8f0;padding:8px;text-align:left;">Max Risk</th>
      </tr>
    </thead>
    <tbody>
      """ + "\n".join(label_rows) + """
    </tbody>
  </table>

  <p style="margin:12px 0 0 0;font-size:13px;">
    Details: <code>reports/asset_match_report.json</code>, <code>reports/asset_match_report.html</code>, and <code>reports/asset_scope_validate_report.json</code>
  </p>
</section>
""" + END

def inject_card(dashboard_html, card):
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    dashboard_html = pattern.sub("", dashboard_html)

    dashboard_html = re.sub(r"</bo\s*$", "", dashboard_html, flags=re.IGNORECASE)
    dashboard_html = re.sub(r"ody>\s*</html>\s*$", "", dashboard_html, flags=re.IGNORECASE)
    dashboard_html = re.sub(r"</body>\s*ml>\s*$", "", dashboard_html, flags=re.IGNORECASE)
    dashboard_html = re.sub(r"</body>\s*</html>\s*$", "", dashboard_html, flags=re.IGNORECASE)
    dashboard_html = dashboard_html.replace("\\n<tr>", "\n<tr>")

    return dashboard_html.rstrip() + "\n" + card + "\n</body>\n</html>\n"

def main():
    REPORTS.mkdir(exist_ok=True)

    if not DASHBOARD.exists():
        print("DASHBOARD_ASSET_CARD_SKIPPED")
        print("reason=dashboard.html missing")
        return 0

    data, error = safe_load_json(ASSET_REPORT)
    card = build_card(data, error=error)

    current = DASHBOARD.read_text(encoding="utf-8-sig", errors="replace")
    updated = inject_card(current, card)
    DASHBOARD.write_text(updated, encoding="utf-8")

    print("DASHBOARD_ASSET_CARD_OK")
    print("dashboard=" + str(DASHBOARD))
    print("asset_report=" + str(ASSET_REPORT))
    if error:
        print("asset_report_status=skipped")
        print("reason=" + error)
    else:
        summary = data.get("summary", {})
        print("asset_report_status=" + str(data.get("status")))
        print("record_count=" + str(summary.get("record_count", 0)))
        print("match_count=" + str(summary.get("match_count", 0)))
        print("max_risk_score=" + str(summary.get("max_risk_score", 0)))

    scope = scope_summary()
    print("registry_mode=" + str(scope.get("active_registry_mode")))
    print("active_asset_count=" + str(scope.get("active_asset_count")))
    print("active_match_value_count=" + str(scope.get("active_match_value_count")))
    print("local_asset_count=" + str(scope.get("local_asset_count")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

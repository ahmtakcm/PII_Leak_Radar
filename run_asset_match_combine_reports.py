import html
import json
from datetime import datetime
from pathlib import Path

from core.reporting import build_report

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"

INPUTS = [
    ("export_parse", REPORTS / "asset_match_export_parse.json"),
    ("manual_import", REPORTS / "asset_match_manual_import.json"),
    ("source_registry", REPORTS / "asset_match_source_registry.json"),
]

def load_report(label, path):
    if not path.exists():
        return {
            "status": "skipped",
            "label": label,
            "reason": "missing",
            "summary": {"record_count": 0, "match_count": 0, "asset_count": 0, "max_risk_score": 0},
            "matches": [],
        }

    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        data.setdefault("label", label)
        data.setdefault("matches", [])
        data.setdefault("summary", {"record_count": 0, "match_count": 0, "asset_count": 0, "max_risk_score": 0})
        return data
    except Exception as exc:
        return {
            "status": "skipped",
            "label": label,
            "reason": "json_error: " + str(exc),
            "summary": {"record_count": 0, "match_count": 0, "asset_count": 0, "max_risk_score": 0},
            "matches": [],
        }

def write_html(report, path):
    summary = report.get("summary", {})
    rows = []

    for item in report.get("matches", []):
        rows.append(
            "<tr>"
            + "<td>" + html.escape(str(item.get("report_label", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("record_path", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("asset_id", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("value_type", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("match_type", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("risk_score", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("matched_value_masked", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("snippet_masked", ""))) + "</td>"
            + "</tr>"
        )

    by_label_items = []
    for label, item in report.get("by_label", {}).items():
        s = item.get("summary", {})
        by_label_items.append(
            "<li>"
            + html.escape(str(label))
            + ": records=" + html.escape(str(s.get("record_count", 0)))
            + ", matches=" + html.escape(str(s.get("match_count", 0)))
            + ", status=" + html.escape(str(item.get("status")))
            + "</li>"
        )

    body = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Asset Match Combined Report</title>
<style>
body{{font-family:Arial;margin:24px}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:6px;vertical-align:top}}
th{{background:#f3f3f3}}
</style>
</head>
<body>
<h1>Asset Match Combined Report</h1>
<p>Status: <b>{status}</b></p>
<p>Total records: {records} | Total matches: {matches} | Assets: {assets} | Max risk: {risk}</p>
<h2>By Label</h2>
<ul>
{by_label}
</ul>
<h2>Matches</h2>
<table>
<tr><th>Label</th><th>Record</th><th>Asset</th><th>Type</th><th>Match</th><th>Risk</th><th>Value</th><th>Snippet</th></tr>
{rows}
</table>
</body>
</html>
""".format(
        status=html.escape(str(report.get("status"))),
        records=html.escape(str(summary.get("record_count", 0))),
        matches=html.escape(str(summary.get("match_count", 0))),
        assets=html.escape(str(summary.get("asset_count", 0))),
        risk=html.escape(str(summary.get("max_risk_score", 0))),
        by_label="\n".join(by_label_items),
        rows="\n".join(rows),
    )

    path.write_text(body, encoding="utf-8")

def main():
    REPORTS.mkdir(exist_ok=True)

    loaded = {}
    all_matches = []
    total_records = 0
    max_score = 0
    by_asset = {}

    for label, path in INPUTS:
        data = load_report(label, path)
        loaded[label] = {
            "status": data.get("status"),
            "reason": data.get("reason"),
            "summary": data.get("summary", {}),
        }

        total_records += int(data.get("summary", {}).get("record_count", 0))

        for match in data.get("matches", []):
            match.setdefault("report_label", label)
            all_matches.append(match)

            aid = str(match.get("asset_id"))
            by_asset[aid] = by_asset.get(aid, 0) + 1
            max_score = max(max_score, int(match.get("risk_score", 0)))

    all_matches.sort(key=lambda x: int(x.get("risk_score", 0)), reverse=True)

    result = {
        "status": "ok",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "record_count": total_records,
            "match_count": len(all_matches),
            "asset_count": len(by_asset),
            "max_risk_score": max_score,
            "by_asset": by_asset,
        },
        "by_label": loaded,
        "matches": all_matches,
    }
    result["report_schema"] = build_report(
        "asset_match_combined",
        summary={
            "record_count": total_records,
            "match_count": len(all_matches),
            "asset_count": len(by_asset),
            "max_risk_score": max_score,
        },
        warnings=[
            f"{label}:{item.get('reason')}"
            for label, item in loaded.items()
            if item.get("status") != "ok" and item.get("reason")
        ],
        inputs={"reports": [str(path) for _, path in INPUTS]},
        outputs={
            "json": str(REPORTS / "asset_match_report.json"),
            "html": str(REPORTS / "asset_match_report.html"),
        },
        data={"labels": list(loaded.keys())},
        raw_sensitive_output=False,
    )

    json_path = REPORTS / "asset_match_report.json"
    html_path = REPORTS / "asset_match_report.html"

    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    write_html(result, html_path)

    print("ASSET_MATCH_COMBINED_OK")
    print("record_count=" + str(total_records))
    print("match_count=" + str(len(all_matches)))
    print("asset_count=" + str(len(by_asset)))
    print("max_risk_score=" + str(max_score))
    print("json=" + str(json_path))
    print("html=" + str(html_path))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


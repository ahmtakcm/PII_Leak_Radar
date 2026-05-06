import argparse
import html
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.match_engine import scan_text
from core.reporting import build_report

def load_json(path):
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    if not p.exists():
        return None, p, "missing"
    try:
        return json.loads(p.read_text(encoding="utf-8-sig")), p, None
    except Exception as exc:
        return None, p, "json_error: " + str(exc)

def is_primitive(value):
    return isinstance(value, (str, int, float, bool))

def walk_records(obj, path="$"):
    if isinstance(obj, dict):
        lines = []
        for key, value in obj.items():
            if is_primitive(value):
                text = str(value).strip()
                if text:
                    lines.append(str(key) + ": " + text)
        if lines:
            yield path, "\n".join(lines)
        for key, value in obj.items():
            if isinstance(value, (dict, list)):
                yield from walk_records(value, path + "." + str(key))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from walk_records(value, path + "[" + str(index) + "]")

def extract_scan_payload(data):
    if isinstance(data, dict):
        for key in ("hits", "events", "files", "matches"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        schema = data.get("report_schema")
        if isinstance(schema, dict):
            nested = schema.get("data", {})
            if isinstance(nested, dict):
                for key in ("legacy_hits", "legacy_events"):
                    value = nested.get(key)
                    if isinstance(value, list):
                        return value
    return data

def attach_report_schema(result, out_path, html_path):
    summary = result.get("summary", {})
    result["report_schema"] = build_report(
        "asset_match_pipeline",
        summary={
            "label": result.get("label"),
            "record_count": summary.get("record_count", 0),
            "match_count": summary.get("match_count", 0),
            "asset_count": summary.get("asset_count", 0),
            "max_risk_score": summary.get("max_risk_score", 0),
        },
        warnings=[] if result.get("status") == "ok" else [result.get("reason", result.get("status"))],
        inputs={"source_report": result.get("source_report")},
        outputs={"json": str(out_path), "html": str(html_path)},
        data={"label": result.get("label")},
        raw_sensitive_output=False,
    )
    return result

def write_html(report, out_path):
    summary = report.get("summary", {})
    rows = []
    for item in report.get("matches", []):
        rows.append("<tr>"
            + "<td>" + html.escape(str(item.get("record_path", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("asset_id", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("value_type", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("match_type", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("risk_score", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("matched_value_masked", ""))) + "</td>"
            + "<td>" + html.escape(str(item.get("snippet_masked", ""))) + "</td>"
            + "</tr>")
    body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Asset Match Report</title>"
    body += "<style>body{font-family:Arial;margin:24px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px;vertical-align:top}th{background:#f3f3f3}</style></head><body>"
    body += "<h1>Asset Match Report</h1>"
    body += "<p>Status: " + html.escape(str(report.get("status"))) + "</p>"
    body += "<p>Target: " + html.escape(str(report.get("label"))) + " | Records: " + html.escape(str(summary.get("record_count"))) + " | Matches: " + html.escape(str(summary.get("match_count"))) + " | Max Risk: " + html.escape(str(summary.get("max_risk_score"))) + "</p>"
    body += "<table><tr><th>Record</th><th>Asset</th><th>Type</th><th>Match</th><th>Risk</th><th>Value</th><th>Snippet</th></tr>"
    body += "\n".join(rows)
    body += "</table></body></html>"
    Path(out_path).write_text(body, encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="reports/export_parse_results.json")
    ap.add_argument("--label", default="export_parse")
    ap.add_argument("--out", default="reports/asset_match_export_parse.json")
    ap.add_argument("--html", default="reports/asset_match_export_parse.html")
    args = ap.parse_args()

    data, report_path, error = load_json(args.report)
    out_path = Path(args.out)
    html_path = Path(args.html)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    if not html_path.is_absolute():
        html_path = ROOT / html_path
    out_path.parent.mkdir(exist_ok=True)
    html_path.parent.mkdir(exist_ok=True)

    if error:
        result = {"status": "skipped", "label": args.label, "reason": error, "source_report": str(report_path), "summary": {"record_count": 0, "match_count": 0, "asset_count": 0, "max_risk_score": 0}, "matches": []}
        result = attach_report_schema(result, out_path, html_path)
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        write_html(result, html_path)
        print("PIPELINE_ASSET_MATCH_SKIPPED")
        print("reason=" + error)
        print("json=" + str(out_path))
        print("html=" + str(html_path))
        return 0

    matches = []
    record_count = 0
    scan_payload = extract_scan_payload(data)
    for record_path, text in walk_records(scan_payload):
        record_count += 1
        scan = scan_text(text, source_id=args.label + ":" + record_path, source_type=args.label)
        for match in scan.get("matches", []):
            match["record_path"] = record_path
            match["report_label"] = args.label
            matches.append(match)

    by_asset = {}
    max_score = 0
    for m in matches:
        aid = str(m.get("asset_id"))
        by_asset[aid] = by_asset.get(aid, 0) + 1
        max_score = max(max_score, int(m.get("risk_score", 0)))

    result = {"status": "ok", "checked_at": datetime.now().isoformat(timespec="seconds"), "label": args.label, "source_report": str(report_path), "summary": {"record_count": record_count, "match_count": len(matches), "asset_count": len(by_asset), "max_risk_score": max_score, "by_asset": by_asset}, "matches": matches}
    result = attach_report_schema(result, out_path, html_path)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    write_html(result, html_path)

    print("PIPELINE_ASSET_MATCH_OK")
    print("label=" + args.label)
    print("source_report=" + str(report_path))
    print("record_count=" + str(record_count))
    print("match_count=" + str(len(matches)))
    print("asset_count=" + str(len(by_asset)))
    print("max_risk_score=" + str(max_score))
    print("json=" + str(out_path))
    print("html=" + str(html_path))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

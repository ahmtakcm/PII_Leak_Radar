import html
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config"
REPORTS = ROOT / "reports"

POLICY_PATH = CONFIG / "source_registry_policy.json"
JSON_REPORT = REPORTS / "source_registry_policy_validate_report.json"
HTML_REPORT = REPORTS / "source_registry_policy_validate_report.html"

REQUIRED_FALSE_RULES = [
    "closed_group_intrusion_allowed",
    "illegal_market_crawling_allowed",
    "credential_use_allowed",
    "bypass_allowed",
]

REQUIRED_TRUE_RULES = [
    "public_open_feeds_can_auto_run",
    "user_provided_exports_can_run",
    "manual_import_can_run",
    "scoped_public_code_search_requires_scope",
    "owned_chat_ingest_requires_allowlist",
    "paste_sources_require_manual_review",
    "high_risk_sources_require_legal_review",
]

def load_policy():
    if not POLICY_PATH.exists():
        return None, "missing"
    try:
        data = json.loads(POLICY_PATH.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            return None, "root_not_object"
        return data, None
    except Exception as exc:
        return None, "json_error: " + str(exc)

def validate_policy(policy):
    errors = []
    warnings = []

    rules = policy.get("policy_rules", {})
    if not isinstance(rules, dict):
        errors.append("policy_rules_missing_or_invalid")
        rules = {}

    for key in REQUIRED_FALSE_RULES:
        if rules.get(key) is not False:
            errors.append("required_false_rule_failed:" + key)

    for key in REQUIRED_TRUE_RULES:
        if rules.get(key) is not True:
            errors.append("required_true_rule_failed:" + key)

    source_classes = policy.get("source_classes", [])
    if not isinstance(source_classes, list):
        errors.append("source_classes_not_list")
        source_classes = []

    existing_sources = policy.get("existing_sources_policy", [])
    if not isinstance(existing_sources, list):
        errors.append("existing_sources_policy_not_list")
        existing_sources = []

    class_ids = set()
    activation_by_status = {}

    for item in source_classes:
        if not isinstance(item, dict):
            warnings.append("source_class_not_object")
            continue

        class_id = str(item.get("class_id", "")).strip()
        status = str(item.get("activation_status", "unknown")).strip()

        if not class_id:
            errors.append("source_class_missing_class_id")
        else:
            if class_id in class_ids:
                errors.append("duplicate_class_id:" + class_id)
            class_ids.add(class_id)

        activation_by_status[status] = activation_by_status.get(status, 0) + 1

    missing_class_refs = []
    target_status_counts = {}

    for item in existing_sources:
        if not isinstance(item, dict):
            warnings.append("existing_source_not_object")
            continue

        source_id = str(item.get("source_id", "")).strip()
        class_id = str(item.get("class_id", "")).strip()
        target_status = str(item.get("target_status", "unknown")).strip()

        if not source_id:
            errors.append("existing_source_missing_source_id")

        if class_id and class_id not in class_ids:
            missing_class_refs.append({"source_id": source_id, "class_id": class_id})

        target_status_counts[target_status] = target_status_counts.get(target_status, 0) + 1

    if missing_class_refs:
        for ref in missing_class_refs:
            errors.append("existing_source_class_ref_missing:" + ref["source_id"] + ":" + ref["class_id"])

    high_risk_ok = False
    for item in source_classes:
        if isinstance(item, dict) and item.get("class_id") == "high_risk_context":
            high_risk_ok = item.get("activation_status") == "legal_review_required"

    if not high_risk_ok:
        errors.append("high_risk_context_not_legal_review_required")

    return {
        "errors": errors,
        "warnings": warnings,
        "source_class_count": len(source_classes),
        "existing_source_policy_count": len(existing_sources),
        "activation_by_status": activation_by_status,
        "target_status_counts": target_status_counts,
        "missing_class_refs": missing_class_refs,
    }

def write_html(report):
    validation = report.get("validation", {})
    rows = []

    for key, value in validation.get("activation_by_status", {}).items():
        rows.append("<tr><td>" + html.escape(str(key)) + "</td><td>" + html.escape(str(value)) + "</td></tr>")

    if not rows:
        rows.append("<tr><td colspan='2'>No activation status data.</td></tr>")

    errors = validation.get("errors", [])
    warnings = validation.get("warnings", [])

    status = html.escape(str(report.get("status")))
    status_class = "ok" if report.get("status") == "ok" else "fail"
    source_classes = html.escape(str(validation.get("source_class_count", 0)))
    existing_sources = html.escape(str(validation.get("existing_source_policy_count", 0)))
    error_text = html.escape(json.dumps(errors, ensure_ascii=False, indent=2))
    warning_text = html.escape(json.dumps(warnings, ensure_ascii=False, indent=2))

    body = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Source Registry Policy Validate Report</title>
<style>
body{{font-family:Arial;margin:24px}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
td,th{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#f3f3f3}}
.ok{{color:green;font-weight:bold}}
.fail{{color:#b91c1c;font-weight:bold}}
</style>
</head>
<body>
<h1>Source Registry Policy Validate Report</h1>
<p>Status: <span class="{status_class}">{status}</span></p>
<p>Source classes: {source_classes} | Existing source policies: {existing_sources}</p>
<h2>Activation Status</h2>
<table>
<tr><th>Status</th><th>Count</th></tr>
{rows}
</table>
<h2>Errors</h2>
<pre>{error_text}</pre>
<h2>Warnings</h2>
<pre>{warning_text}</pre>
</body>
</html>
"""

    HTML_REPORT.write_text(body, encoding="utf-8")

def main():
    print("SOURCE_REGISTRY_POLICY_VALIDATE")

    REPORTS.mkdir(exist_ok=True)

    policy, error = load_policy()
    if error:
        report = {
            "status": "fail",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "policy_path": str(POLICY_PATH),
            "reason": error,
        }
        JSON_REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        write_html(report)
        print("status=fail")
        print("reason=" + error)
        print("json=" + str(JSON_REPORT))
        print("html=" + str(HTML_REPORT))
        return 1

    validation = validate_policy(policy)
    ok = len(validation.get("errors", [])) == 0

    report = {
        "status": "ok" if ok else "fail",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "policy_path": str(POLICY_PATH),
        "mode": policy.get("mode"),
        "alerts_enabled": policy.get("alerts_enabled"),
        "mask_sensitive": policy.get("mask_sensitive"),
        "raw_sensitive_output": policy.get("raw_sensitive_output"),
        "validation": validation,
    }

    JSON_REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_html(report)

    print("status=" + report["status"])
    print("mode=" + str(report.get("mode")))
    print("alerts_enabled=" + str(report.get("alerts_enabled")))
    print("mask_sensitive=" + str(report.get("mask_sensitive")))
    print("raw_sensitive_output=" + str(report.get("raw_sensitive_output")))
    print("source_class_count=" + str(validation.get("source_class_count")))
    print("existing_source_policy_count=" + str(validation.get("existing_source_policy_count")))
    print("error_count=" + str(len(validation.get("errors", []))))
    print("warning_count=" + str(len(validation.get("warnings", []))))
    print("json=" + str(JSON_REPORT))
    print("html=" + str(HTML_REPORT))

    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())

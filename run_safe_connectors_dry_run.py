from __future__ import annotations

import json
import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from connectors.registry import ConnectorRegistry
from core.reporting import build_report


PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_ROOT / "config" / "source_registry_policy.json"
REPORTS_DIR = PROJECT_ROOT / "reports"
JSON_OUT = REPORTS_DIR / "safe_connectors_dry_run_results.json"
HTML_OUT = REPORTS_DIR / "safe_connectors_dry_run_report.html"

RUNTIME_POLICY = {
    "mode": "dry-run",
    "network_enabled": False,
    "alerts_enabled": False,
    "auth_enabled": False,
    "credential_use_enabled": False,
    "mask_sensitive": True,
    "raw_sensitive_output": False,
}

HIGH_RISK_CLASS_IDS = {
    "high_risk_context",
}

MANUAL_REVIEW_CLASS_IDS = {
    "paste_manual_review",
    "high_risk_context",
    "scoped_public_code_search",
}

MANUAL_REVIEW_STATUSES = {
    "scope_required",
    "manual_review_required",
    "legal_review_required",
    "allowlist_required",
}

CONTROL_WORDS = {
    "dry_run",
    "mask_sensitive",
    "offline_parse_only",
    "no_auto_join",
    "no_raw_credential_collection",
    "no_bulk_scrape",
    "no_access_or_transaction",
    "manual_legal_review",
    "risk_classification_only",
    "valid_api_key",
    "open_api_terms",
    "bot_authorized_by_owner",
    "allowed_channel_or_group_id",
    "allowed_server_or_channel_id",
    "allowed_domains_or_keywords",
    "no_secret_exposure",
    "no_auth_required",
    "open_public_web",
    "config_scope_yml_defined",
    "manual_source_submission",
    "user_supplied_file",
    "user_supplied_file_or_note",
    "open_public_source",
}

RISK_PATTERNS = [
    ("credential_context", ("credential", "creds", "password", "token", "cookie", "session")),
    ("leak_or_paste_context", ("leak", "paste", "dump", "breach")),
    ("chat_or_invite_context", ("telegram", "discord", "invite", "group", "channel", "server")),
    ("high_risk_market_or_panel_context", ("market", "panel", "darkweb", "illegal", "closed_group")),
    ("review_gate_context", ("manual_review", "legal_review", "scope_required", "allowlist")),
]


def load_policy(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def normalize_id(value: Any) -> str:
    text = str(value or "").strip()
    text = text.replace(" ", "_").replace("-", "_").lower()
    allowed = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            allowed.append(ch)
    return "".join(allowed).strip("_")


def class_map(policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for item in policy.get("source_classes", []) or []:
        if isinstance(item, dict):
            cid = normalize_id(item.get("class_id"))
            if cid:
                result[cid] = item
    return result


def derive_missing_source_id(
    record: Dict[str, Any],
    classes: Dict[str, Dict[str, Any]],
    used_ids: set[str],
    index: int,
) -> str:
    class_id = normalize_id(record.get("class_id"))
    class_def = classes.get(class_id, {})
    for candidate in class_def.get("examples", []) or []:
        cid = normalize_id(candidate)
        if cid and cid not in used_ids and cid not in CONTROL_WORDS:
            return cid
    fallback = f"{class_id or 'source'}_{index}"
    while fallback in used_ids:
        fallback = f"{fallback}_dup"
    return fallback


def extract_sources(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    classes = class_map(policy)
    raw_sources = policy.get("existing_sources_policy", []) or []
    sources: List[Dict[str, Any]] = []
    used: set[str] = set()

    for idx, raw in enumerate(raw_sources):
        if not isinstance(raw, dict):
            continue
        rec = dict(raw)
        sid = normalize_id(rec.get("source_id"))
        if not sid:
            sid = derive_missing_source_id(rec, classes, used, idx)
            rec["derived_source_id"] = True
        else:
            rec["derived_source_id"] = False
        rec["source_id"] = sid
        rec["class_id"] = normalize_id(rec.get("class_id"))
        rec["current_status"] = normalize_id(rec.get("current_status"))
        rec["target_status"] = normalize_id(rec.get("target_status"))
        rec["policy_index"] = idx
        used.add(sid)
        sources.append(rec)

    return sources


def classify_policy_status(source: Dict[str, Any], classes: Dict[str, Dict[str, Any]]) -> str:
    sid = source.get("source_id", "")
    class_id = source.get("class_id", "")
    current = source.get("current_status", "")
    target = source.get("target_status", "")
    class_def = classes.get(class_id, {})
    activation = normalize_id(class_def.get("activation_status"))

    joined = " ".join([sid, class_id, current, target, activation])

    if "legal_review" in joined or class_id in HIGH_RISK_CLASS_IDS:
        return "manual_review"
    if "manual_review" in joined or "scope_required" in joined or "allowlist_required" in joined:
        return "manual_review"
    if class_id in MANUAL_REVIEW_CLASS_IDS:
        return "manual_review"
    if current == "disabled" or target == "disabled":
        return "disabled"
    if "blocked" in joined or "disallowed" in joined:
        return "blocked"
    if activation in MANUAL_REVIEW_STATUSES:
        return "manual_review"
    return "allowed"


def detect_risk_context(source: Dict[str, Any]) -> List[str]:
    text = " ".join(str(v) for v in source.values() if isinstance(v, (str, int, bool))).lower()
    risks: List[str] = []
    for label, needles in RISK_PATTERNS:
        if any(needle in text for needle in needles):
            risks.append(label)
    return risks


def adapter_decision(source: Dict[str, Any], policy_status: str) -> Dict[str, Any]:
    adapter = ConnectorRegistry.build(source, RUNTIME_POLICY)
    adapter_name = ConnectorRegistry.adapter_name_for(source.get("source_id", ""), source.get("class_id", ""))
    adapter_available = adapter is not None

    block_reasons: List[str] = []
    notes: List[str] = []

    if policy_status == "manual_review":
        block_reasons.append("manual_review_required")
    elif policy_status == "blocked":
        block_reasons.append("blocked_by_policy")
    elif policy_status == "disabled":
        block_reasons.append("disabled_by_policy")

    if not adapter_available:
        block_reasons.append("adapter_not_implemented")

    connector_decision = None
    if adapter:
        connector_decision = adapter.dry_run().to_dict()
        for reason in connector_decision.get("block_reasons", []) or []:
            if reason not in block_reasons:
                block_reasons.append(reason)
        notes.extend(connector_decision.get("notes", []) or [])

    class_id = source.get("class_id", "")
    if class_id == "open_api_requires_key":
        notes.append("open API adapter requires configured key/terms before live use; this runner does not read credentials")

    can_run = (
        policy_status == "allowed"
        and adapter_available
        and not any(reason in block_reasons for reason in ["auth_disabled", "credential_use_disabled", "adapter_not_implemented"])
    )

    run_mode = "dry-run-metadata-only" if can_run else "not-runnable-dry-run"

    return {
        "adapter_available": adapter_available,
        "adapter_name": adapter_name,
        "can_run": can_run,
        "run_mode": run_mode,
        "block_reasons": block_reasons,
        "notes": sorted(set(notes)),
        "connector_decision": connector_decision,
    }


def build_results() -> Dict[str, Any]:
    policy = load_policy(CONFIG_PATH)
    classes = class_map(policy)
    sources = extract_sources(policy)

    source_rows: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for source in sources:
        policy_status = classify_policy_status(source, classes)
        risks = detect_risk_context(source)
        decision = adapter_decision(source, policy_status)

        row = {
            "source_id": source.get("source_id"),
            "class_id": source.get("class_id"),
            "policy_status": policy_status,
            "current_status": source.get("current_status"),
            "target_status": source.get("target_status"),
            "derived_source_id": bool(source.get("derived_source_id")),
            "risk_contexts": risks,
            **decision,
        }

        if decision["adapter_available"] is False and policy_status == "allowed":
            warnings.append(f"adapter_missing_for_allowed_source: {source.get('source_id')}")
        if source.get("class_id") == "high_risk_context" and policy_status != "manual_review":
            warnings.append(f"high_risk_source_not_manual_review: {source.get('source_id')}")

        source_rows.append(row)

    adapter_available_count = sum(1 for s in source_rows if s["adapter_available"])
    adapter_missing_count = sum(1 for s in source_rows if not s["adapter_available"])
    can_run_count = sum(1 for s in source_rows if s["can_run"])
    blocked_count = sum(1 for s in source_rows if not s["can_run"])
    allowed_count = sum(1 for s in source_rows if s["policy_status"] == "allowed")
    manual_review_count = sum(1 for s in source_rows if s["policy_status"] == "manual_review")
    policy_blocked_count = sum(1 for s in source_rows if s["policy_status"] == "blocked")
    disabled_count = sum(1 for s in source_rows if s["policy_status"] == "disabled")

    summary = {
        "status": "ok",
        **RUNTIME_POLICY,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "policy_path": str(CONFIG_PATH),
        "source_count": len(source_rows),
        "allowed_count": allowed_count,
        "manual_review_count": manual_review_count,
        "policy_blocked_count": policy_blocked_count,
        "disabled_count": disabled_count,
        "adapter_available_count": adapter_available_count,
        "adapter_missing_count": adapter_missing_count,
        "can_run_count": can_run_count,
        "dry_run_blocked_count": blocked_count,
        "warning_count": len(warnings),
    }

    report = build_report(
        "safe_connectors_dry_run",
        summary=summary,
        warnings=warnings,
        inputs={"policy_path": str(CONFIG_PATH)},
        outputs={"json": str(JSON_OUT), "html": str(HTML_OUT)},
        data={"source_count": len(source_rows)},
        raw_sensitive_output=False,
    )

    return {
        **summary,
        "summary": summary,
        "sources": source_rows,
        "warnings": warnings,
        "report_schema": report,
        "debug": {
            "schema_locked_to": "top_level.existing_sources_policy",
            "source_classes_count": len(classes),
            "existing_sources_policy_count": len(policy.get("existing_sources_policy", []) or []),
            "registered_source_adapters": sorted(ConnectorRegistry.SOURCE_ADAPTERS.keys()),
            "registered_class_fallback_adapters": sorted(ConnectorRegistry.CLASS_FALLBACK_ADAPTERS.keys()),
        },
    }


def render_html(results: Dict[str, Any]) -> str:
    summary = results.get("summary", {})
    sources = results.get("sources", [])
    warnings = results.get("warnings", [])

    def esc(x: Any) -> str:
        return html.escape(str(x if x is not None else "-"))

    summary_rows = "\n".join(
        f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
        for k, v in summary.items()
        if k not in {"policy_path"}
    )

    warning_html = "<p>No warnings.</p>" if not warnings else "<ul>" + "".join(f"<li>{esc(w)}</li>" for w in warnings) + "</ul>"

    source_rows = []
    for s in sources:
        block = ", ".join(s.get("block_reasons") or []) or "-"
        risks = ", ".join(s.get("risk_contexts") or []) or "-"
        notes = "; ".join(s.get("notes") or []) or "-"
        source_rows.append(
            "<tr>"
            f"<td>{esc(s.get('source_id'))}</td>"
            f"<td>{esc(s.get('policy_status'))}</td>"
            f"<td>{esc(s.get('class_id'))}</td>"
            f"<td>{esc(s.get('adapter_name') or '-')}</td>"
            f"<td>{esc(s.get('adapter_available'))}</td>"
            f"<td>{esc(s.get('can_run'))}</td>"
            f"<td>{esc(s.get('run_mode'))}</td>"
            f"<td>{esc(block)}</td>"
            f"<td>{esc(risks)}</td>"
            f"<td>{esc(notes)}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>PII Leak Radar - Safe Connectors Dry-Run</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #f7f7f7; color: #111; }}
    h1, h2 {{ margin-bottom: 8px; }}
    .card {{ background: #fff; border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 16px 0; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; font-size: 13px; }}
    th {{ background: #f0f0f0; text-align: left; }}
    .safe {{ color: #166534; font-weight: bold; }}
    .warn {{ color: #92400e; font-weight: bold; }}
    code {{ background: #eee; padding: 2px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>PII Leak Radar - Safe Connectors Dry-Run</h1>
  <p class="safe">Dry-run only. Network/auth/credential/alert usage disabled. Sanitized metadata-only report.</p>

  <div class="card">
    <h2>Summary</h2>
    <table>{summary_rows}</table>
  </div>

  <div class="card">
    <h2>Warnings</h2>
    {warning_html}
  </div>

  <div class="card">
    <h2>Sources and Adapter Decisions</h2>
    <table>
      <thead>
        <tr>
          <th>Source ID</th>
          <th>Policy Status</th>
          <th>Class</th>
          <th>Adapter</th>
          <th>Adapter Available</th>
          <th>Can Run</th>
          <th>Run Mode</th>
          <th>Block Reasons</th>
          <th>Risk Contexts</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        {''.join(source_rows)}
      </tbody>
    </table>
  </div>
</body>
</html>
"""


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    results = build_results()
    JSON_OUT.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    HTML_OUT.write_text(render_html(results), encoding="utf-8")

    s = results["summary"]
    print("SAFE_CONNECTORS_DRY_RUN")
    for key in [
        "status",
        "mode",
        "network_enabled",
        "alerts_enabled",
        "auth_enabled",
        "credential_use_enabled",
        "mask_sensitive",
        "raw_sensitive_output",
        "source_count",
        "allowed_count",
        "manual_review_count",
        "policy_blocked_count",
        "disabled_count",
        "adapter_available_count",
        "adapter_missing_count",
        "can_run_count",
        "dry_run_blocked_count",
        "warning_count",
    ]:
        print(f"{key}={s.get(key)}")
    print(f"json={JSON_OUT}")
    print(f"html={HTML_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

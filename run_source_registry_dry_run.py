#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PII Leak Radar - Step 46G
Source Registry Dry-Run Connector Runner (schema-locked)

Reads config/source_registry_policy.json offline and reports only real source entries
from existing_sources_policy. It does not run connectors, perform network access,
use credentials, join groups, crawl illegal markets, bypass access controls, or emit alerts.
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "config" / "source_registry_policy.json"
REPORTS_DIR = ROOT / "reports"
JSON_OUT = REPORTS_DIR / "source_registry_dry_run_results.json"
HTML_OUT = REPORTS_DIR / "source_registry_dry_run_report.html"

SAFE_FLAGS = {
    "mode": "dry-run",
    "network_enabled": False,
    "alerts_enabled": False,
    "auth_enabled": False,
    "credential_use_enabled": False,
    "mask_sensitive": True,
    "raw_sensitive_output": False,
}

RISK_KEYWORDS = [
    "leak", "dump", "breach", "credential", "combo", "paste", "darkweb",
    "dark_web", "illegal", "market", "panel", "invite", "telegram", "discord",
    "closed_group", "kapalı", "davet", "bot", "sorgu", "gsm", "tc",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8-sig")
    return json.loads(raw)


def as_slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9_\-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "unnamed"


def normalize_status(text: Any) -> str:
    return str(text or "").strip().lower()


def build_class_map(policy: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    class_map: Dict[str, Dict[str, Any]] = {}
    for item in policy.get("source_classes", []) or []:
        if not isinstance(item, dict):
            continue
        class_id = as_slug(item.get("class_id"))
        class_map[class_id] = {
            "class_id": class_id,
            "activation_status": normalize_status(item.get("activation_status")),
            "examples": [as_slug(x) for x in (item.get("examples") or []) if str(x or "").strip()],
            "requirements": [as_slug(x) for x in (item.get("requirements") or []) if str(x or "").strip()],
            "raw": item,
        }
    return class_map


def infer_missing_source_id(
    index: int,
    entry: Dict[str, Any],
    class_map: Dict[str, Dict[str, Any]],
    used_ids: set[str],
) -> Tuple[str, str, str]:
    """Return source_id, method, note for entries with blank/missing source_id."""
    class_id = as_slug(entry.get("class_id"))
    examples = class_map.get(class_id, {}).get("examples", [])
    for example in examples:
        if example and example not in used_ids:
            return example, "class_example_rescue", f"source_id missing/blank at existing_sources_policy[{index}], resolved from source_classes.{class_id}.examples"
    fallback = f"unnamed_source_{index:02d}_{class_id or 'unknown_class'}"
    return fallback, "synthetic_id", f"source_id missing/blank at existing_sources_policy[{index}], synthetic id assigned"


def decide_status(source_id: str, entry: Dict[str, Any], class_info: Dict[str, Any]) -> Tuple[str, List[str], str]:
    """Map policy fields to safe report status buckets."""
    class_id = as_slug(entry.get("class_id"))
    current_status = normalize_status(entry.get("current_status"))
    target_status = normalize_status(entry.get("target_status"))
    activation_status = normalize_status(class_info.get("activation_status"))
    combined = " ".join([source_id, class_id, current_status, target_status, activation_status])

    notes: List[str] = []
    action = "keep dry-run only; no connector execution"

    if any(x in combined for x in ["disabled", "disable"]):
        return "disabled", notes, "keep disabled"
    if any(x in combined for x in ["blocked", "block", "forbidden", "not_allowed"]):
        return "blocked", notes, "keep blocked; do not activate"

    # Things that must remain review-gated even if they are listed in the registry.
    if activation_status in {"scope_required", "manual_review_required", "legal_review_required", "allowlist_required"}:
        status = "manual_review"
        if activation_status == "scope_required":
            action = "manual scope review required before activation"
        elif activation_status == "legal_review_required":
            action = "legal/manual review required; risk classification only"
        elif activation_status == "allowlist_required":
            action = "allowlist required; no auto-join/no unauthorized access"
        else:
            action = "manual review required; offline/sanitized handling only"
        return status, notes, action

    if any(x in combined for x in ["scope_required", "manual_review", "legal_review"]):
        return "manual_review", notes, "manual review required; offline/sanitized handling only"

    if activation_status in {"auto_allowed", "allowed", "auto_allowed_if_key_configured"}:
        if activation_status == "auto_allowed_if_key_configured":
            notes.append("allowed by policy only if configured key/terms are valid; this runner does not use credentials")
            action = "eligible after key/terms verification; dry-run only here"
        elif target_status.startswith("activate_as_manual_import"):
            action = "eligible as user-supplied manual import; offline/sanitized only"
        elif target_status.startswith("activate_as_offline_export_parser"):
            action = "eligible as user-supplied offline export parser; sanitized only"
        else:
            action = "eligible by policy; dry-run only here"
        return "allowed", notes, action

    if target_status.startswith("keep_active") or target_status.startswith("activate_as_open_public_web"):
        return "allowed", notes, "eligible by target policy; dry-run only here"
    if target_status.startswith("activate_as_manual_import") or target_status.startswith("activate_as_offline_export_parser"):
        return "allowed", notes, "eligible as user-supplied/offline source; sanitized only"

    return "manual_review", notes, "unknown policy status; keep manual review"


def classify_risk_context(source_id: str, class_id: str, entry: Dict[str, Any], class_info: Dict[str, Any]) -> List[str]:
    haystack_parts = [source_id, class_id]
    for key in ("current_status", "target_status", "notes", "description"):
        if key in entry:
            haystack_parts.append(str(entry.get(key)))
    haystack_parts.extend(class_info.get("examples", []) or [])
    haystack_parts.extend(class_info.get("requirements", []) or [])
    text = " ".join(haystack_parts).lower()

    contexts: List[str] = []
    if any(k in text for k in ["leak", "dump", "breach", "paste"]):
        contexts.append("leak_or_paste_context")
    if any(k in text for k in ["credential", "combo"]):
        contexts.append("credential_context")
    if any(k in text for k in ["illegal", "market", "darkweb", "dark_web", "panel"]):
        contexts.append("high_risk_market_or_panel_context")
    if any(k in text for k in ["telegram", "discord", "invite", "closed_group", "davet"]):
        contexts.append("chat_or_invite_context")
    if any(k in text for k in ["scope", "allowlist", "legal_review", "manual_review"]):
        contexts.append("review_gate_context")
    return sorted(set(contexts))


def extract_sources(policy: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str], Dict[str, Any]]:
    class_map = build_class_map(policy)
    existing = policy.get("existing_sources_policy", [])
    warnings: List[str] = []
    sources: List[Dict[str, Any]] = []
    used_ids: set[str] = set()
    duplicate_ids: Dict[str, int] = {}

    if not isinstance(existing, list):
        warnings.append("existing_sources_policy_not_list: expected top-level list")
        existing = []

    for idx, entry in enumerate(existing):
        if not isinstance(entry, dict):
            warnings.append(f"invalid_source_entry: existing_sources_policy[{idx}] is not an object")
            continue

        raw_source_id = str(entry.get("source_id") or "").strip()
        class_id = as_slug(entry.get("class_id"))
        class_info = class_map.get(class_id, {"class_id": class_id, "activation_status": "", "examples": [], "requirements": []})

        note_list: List[str] = []
        if raw_source_id:
            source_id = as_slug(raw_source_id)
            extraction_method = "existing_sources_policy.source_id"
        else:
            source_id, extraction_method, note = infer_missing_source_id(idx, entry, class_map, used_ids)
            note_list.append(note)

        duplicate_ids[source_id] = duplicate_ids.get(source_id, 0) + 1
        used_ids.add(source_id)

        status, status_notes, action = decide_status(source_id, entry, class_info)
        note_list.extend(status_notes)
        risk_context = classify_risk_context(source_id, class_id, entry, class_info)

        source = {
            "source_id": source_id,
            "status": status,
            "class_id": class_id,
            "activation_status": class_info.get("activation_status", ""),
            "current_status": normalize_status(entry.get("current_status")),
            "target_status": normalize_status(entry.get("target_status")),
            "risk_context": risk_context,
            "recommended_action": action,
            "extraction_method": extraction_method,
            "policy_path": f"existing_sources_policy[{idx}]",
            "notes": note_list,
            "requirements": class_info.get("requirements", []),
        }
        sources.append(source)

    for source_id, count in sorted(duplicate_ids.items()):
        if count > 1:
            warnings.append(f"duplicate_source_id: {source_id} count={count}")

    # Safety policy invariants: these must stay false.
    rules = policy.get("policy_rules", {}) or {}
    if rules.get("illegal_market_crawling_allowed") is not False:
        warnings.append("unsafe_policy_rule: illegal_market_crawling_allowed must be false")
    if rules.get("credential_use_allowed") is not False:
        warnings.append("unsafe_policy_rule: credential_use_allowed must be false")
    if rules.get("bypass_allowed") is not False:
        warnings.append("unsafe_policy_rule: bypass_allowed must be false")
    if rules.get("closed_group_intrusion_allowed") is not False:
        warnings.append("unsafe_policy_rule: closed_group_intrusion_allowed must be false")

    debug = {
        "schema_locked_to": "top_level.existing_sources_policy",
        "top_level_keys": list(policy.keys()),
        "source_classes_count": len(policy.get("source_classes", []) or []),
        "existing_sources_policy_count": len(existing),
        "class_ids": sorted(class_map.keys()),
        "missing_source_id_resolutions": [
            {"source_id": s["source_id"], "policy_path": s["policy_path"], "note": s["notes"]}
            for s in sources if s.get("extraction_method") != "existing_sources_policy.source_id"
        ],
    }
    return sources, warnings, debug


def render_html(result: Dict[str, Any]) -> str:
    summary = result.get("summary", {})
    sources = result.get("sources", [])
    warnings = result.get("warnings", [])

    def esc(x: Any) -> str:
        return html.escape(str(x if x is not None else ""))

    rows = []
    for s in sources:
        risk = ", ".join(s.get("risk_context", []) or [])
        notes = "; ".join(s.get("notes", []) or [])
        rows.append(
            "<tr>"
            f"<td><code>{esc(s.get('source_id'))}</code></td>"
            f"<td>{esc(s.get('status'))}</td>"
            f"<td>{esc(s.get('class_id'))}</td>"
            f"<td>{esc(s.get('current_status'))}</td>"
            f"<td>{esc(s.get('target_status'))}</td>"
            f"<td>{esc(risk)}</td>"
            f"<td>{esc(s.get('recommended_action'))}</td>"
            f"<td>{esc(notes)}</td>"
            "</tr>"
        )

    warning_items = "".join(f"<li><code>{esc(w)}</code></li>" for w in warnings) or "<li>None</li>"

    return f"""<!doctype html>
<html lang=\"tr\">
<head>
  <meta charset=\"utf-8\" />
  <title>PII Leak Radar - Source Registry Dry Run</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; line-height: 1.45; color: #222; }}
    h1, h2 {{ margin-bottom: 8px; }}
    .pill {{ display:inline-block; padding:4px 8px; border:1px solid #999; border-radius: 999px; margin: 2px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; font-size: 13px; }}
    th {{ background: #f3f3f3; text-align: left; }}
    code {{ background: #f7f7f7; padding: 1px 3px; border-radius: 4px; }}
    .notice {{ border-left: 4px solid #888; padding: 10px 12px; background: #fafafa; }}
  </style>
</head>
<body>
  <h1>PII Leak Radar - Source Registry Dry Run</h1>
  <div class=\"notice\">
    Offline dry-run report. No network access, no connector execution, no auth/credential use, no alerts.
    High-risk/illegal/leak contexts are classified as defensive risk signals only.
  </div>

  <h2>Summary</h2>
  <div>
    <span class=\"pill\">status: {esc(summary.get('status'))}</span>
    <span class=\"pill\">mode: {esc(summary.get('mode'))}</span>
    <span class=\"pill\">source_count: {esc(summary.get('source_count'))}</span>
    <span class=\"pill\">allowed: {esc(summary.get('allowed_count'))}</span>
    <span class=\"pill\">manual_review: {esc(summary.get('manual_review_count'))}</span>
    <span class=\"pill\">blocked: {esc(summary.get('blocked_count'))}</span>
    <span class=\"pill\">disabled: {esc(summary.get('disabled_count'))}</span>
    <span class=\"pill\">warnings: {esc(summary.get('warning_count'))}</span>
  </div>

  <h2>Warnings</h2>
  <ul>{warning_items}</ul>

  <h2>Sources</h2>
  <table>
    <thead>
      <tr>
        <th>Source ID</th><th>Status</th><th>Class</th><th>Current</th><th>Target</th>
        <th>Risk Context</th><th>Recommended Action</th><th>Notes</th>
      </tr>
    </thead>
    <tbody>{''.join(rows) or '<tr><td colspan="8">No source entries detected.</td></tr>'}</tbody>
  </table>
</body>
</html>"""


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    warnings: List[str] = []
    policy: Dict[str, Any] = {}
    sources: List[Dict[str, Any]] = []
    debug: Dict[str, Any] = {}

    if not POLICY_PATH.exists():
        status = "error"
        warnings.append(f"policy_missing: {POLICY_PATH}")
    else:
        try:
            loaded = read_json(POLICY_PATH)
            if not isinstance(loaded, dict):
                status = "error"
                warnings.append("policy_root_not_object")
            else:
                policy = loaded
                sources, extract_warnings, debug = extract_sources(policy)
                warnings.extend(extract_warnings)
                status = "ok"
        except Exception as exc:  # noqa: BLE001
            status = "error"
            warnings.append(f"policy_parse_error: {type(exc).__name__}: {exc}")

    counts = {
        "source_count": len(sources),
        "allowed_count": sum(1 for s in sources if s.get("status") == "allowed"),
        "manual_review_count": sum(1 for s in sources if s.get("status") == "manual_review"),
        "blocked_count": sum(1 for s in sources if s.get("status") == "blocked"),
        "disabled_count": sum(1 for s in sources if s.get("status") == "disabled"),
        "warning_count": len(warnings),
    }

    summary = {
        "status": status,
        **SAFE_FLAGS,
        **counts,
        "policy_path": str(POLICY_PATH),
        "json_report": str(JSON_OUT),
        "html_report": str(HTML_OUT),
        "generated_at_utc": utc_now(),
    }

    result = {
        "summary": summary,
        **SAFE_FLAGS,
        **counts,
        "sources": sources,
        "warnings": warnings,
        "policy_rules": policy.get("policy_rules", {}) if isinstance(policy, dict) else {},
        "debug": debug,
    }

    JSON_OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    HTML_OUT.write_text(render_html(result), encoding="utf-8")

    print("SOURCE_REGISTRY_DRY_RUN")
    print(f"status={summary['status']}")
    print(f"mode={summary['mode']}")
    print(f"network_enabled={summary['network_enabled']}")
    print(f"alerts_enabled={summary['alerts_enabled']}")
    print(f"auth_enabled={summary['auth_enabled']}")
    print(f"credential_use_enabled={summary['credential_use_enabled']}")
    print(f"mask_sensitive={summary['mask_sensitive']}")
    print(f"raw_sensitive_output={summary['raw_sensitive_output']}")
    for k in ["source_count", "allowed_count", "manual_review_count", "blocked_count", "disabled_count", "warning_count"]:
        print(f"{k}={summary[k]}")
    print(f"json={JSON_OUT}")
    print(f"html={HTML_OUT}")
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())

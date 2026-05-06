from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "reports" / "safe_connectors_dry_run_results.json"
POLICY = ROOT / "config" / "source_registry_policy.json"


def main() -> int:
    print("=== FILES ===")
    print(f"policy_exists: {POLICY.exists()} | {POLICY}")
    if POLICY.exists():
        print(f"policy_size: {POLICY.stat().st_size}")
    print(f"results_exists: {RESULTS.exists()} | {RESULTS}")
    if not RESULTS.exists():
        print("Run first: python .\\run_safe_connectors_dry_run.py")
        return 1

    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    summary = data.get("summary", {})

    print("\n=== SUMMARY ===")
    for key in [
        "status",
        "mode",
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
        "network_enabled",
        "alerts_enabled",
        "auth_enabled",
        "credential_use_enabled",
        "mask_sensitive",
        "raw_sensitive_output",
    ]:
        print(f"{key}: {summary.get(key)}")

    print("\n=== WARNINGS ===")
    warnings = data.get("warnings") or []
    if not warnings:
        print("warning yok")
    else:
        for i, w in enumerate(warnings, 1):
            print(f"[{i}] {w}")

    print("\n=== SOURCES ===")
    for s in data.get("sources", []):
        reasons = ",".join(s.get("block_reasons") or []) or "-"
        risks = ",".join(s.get("risk_contexts") or []) or "-"
        notes = "; ".join(s.get("notes") or []) or "-"
        print(
            f"- {s.get('source_id')} | policy={s.get('policy_status')} | "
            f"class={s.get('class_id')} | adapter={s.get('adapter_name') or '-'} | "
            f"available={s.get('adapter_available')} | can_run={s.get('can_run')} | "
            f"reasons={reasons} | risk={risks} | notes={notes}"
        )

    print("\n=== DEBUG ===")
    debug = data.get("debug", {})
    for k, v in debug.items():
        print(f"{k}: {v}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

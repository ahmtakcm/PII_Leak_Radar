#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inspect Step 46G source registry dry-run results."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "config" / "source_registry_policy.json"
RESULTS_PATH = ROOT / "reports" / "source_registry_dry_run_results.json"


def main() -> int:
    print("=== FILES ===")
    print(f"policy_exists: {POLICY_PATH.exists()} | {POLICY_PATH}")
    if POLICY_PATH.exists():
        print(f"policy_size: {POLICY_PATH.stat().st_size}")
    print(f"results_exists: {RESULTS_PATH.exists()} | {RESULTS_PATH}")

    if not RESULTS_PATH.exists():
        print("\nresults file not found; run: python .\\run_source_registry_dry_run.py")
        return 1

    data = json.loads(RESULTS_PATH.read_text(encoding="utf-8-sig"))
    summary = data.get("summary", data)

    print("\n=== SUMMARY ===")
    for key in [
        "status", "mode", "source_count", "allowed_count", "manual_review_count",
        "blocked_count", "disabled_count", "warning_count", "network_enabled",
        "alerts_enabled", "auth_enabled", "credential_use_enabled",
        "mask_sensitive", "raw_sensitive_output",
    ]:
        print(f"{key}: {summary.get(key)}")

    print("\n=== WARNINGS ===")
    warnings = data.get("warnings", []) or []
    if not warnings:
        print("warning yok")
    else:
        for i, warning in enumerate(warnings, 1):
            print(f"[{i}] {warning}")

    print("\n=== SOURCES ===")
    sources = data.get("sources", []) or []
    if not sources:
        print("source yok")
    else:
        for s in sources:
            risk = ",".join(s.get("risk_context", []) or []) or "-"
            notes = "; ".join(s.get("notes", []) or []) or "-"
            print(
                f"- {s.get('source_id')} | {s.get('status')} | {s.get('class_id')} | "
                f"current={s.get('current_status') or '-'} | target={s.get('target_status') or '-'} | "
                f"risk={risk} | notes={notes}"
            )

    print("\n=== DEBUG ===")
    debug = data.get("debug", {}) or {}
    print(f"schema_locked_to: {debug.get('schema_locked_to')}")
    print(f"source_classes_count: {debug.get('source_classes_count')}")
    print(f"existing_sources_policy_count: {debug.get('existing_sources_policy_count')}")
    missing = debug.get("missing_source_id_resolutions", []) or []
    if missing:
        print("missing_source_id_resolutions:")
        for item in missing:
            print(f"- {item.get('policy_path')} => {item.get('source_id')} | {item.get('note')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

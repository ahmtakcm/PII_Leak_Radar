from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def derive_status(errors: Optional[Iterable[Any]] = None, warnings: Optional[Iterable[Any]] = None) -> str:
    if errors and len(list(errors)) > 0:
        return "error"
    if warnings and len(list(warnings)) > 0:
        return "warning"
    return "ok"


def build_report(
    name: str,
    summary: Optional[Dict[str, Any]] = None,
    warnings: Optional[Iterable[Any]] = None,
    errors: Optional[Iterable[Any]] = None,
    inputs: Optional[Dict[str, Any]] = None,
    outputs: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    raw_sensitive_output: bool = False,
) -> Dict[str, Any]:
    warning_list = list(warnings or [])
    error_list = list(errors or [])
    return {
        "name": name,
        "generated_at_utc": utc_now_iso(),
        "status": derive_status(error_list, warning_list),
        "summary": summary or {},
        "warnings": warning_list,
        "errors": error_list,
        "inputs": inputs or {},
        "outputs": outputs or {},
        "raw_sensitive_output": bool(raw_sensitive_output),
        "data": data or {},
    }


def write_json_report(path: Path, report: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path

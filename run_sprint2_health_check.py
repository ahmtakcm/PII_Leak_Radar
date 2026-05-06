import json
import py_compile
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def check_file(path):
    return {
        "name": str(path.relative_to(ROOT)),
        "exists": path.exists(),
        "size": path.stat().st_size if path.exists() else 0,
    }

def compile_python(path):
    try:
        py_compile.compile(str(path), doraise=True)
        return {"file": str(path.relative_to(ROOT)), "ok": True, "error": None}
    except Exception as exc:
        return {"file": str(path.relative_to(ROOT)), "ok": False, "error": str(exc)}

def build_registry_test_text(registry):
    chosen = []
    wanted = ["email", "phone", "domain", "username", "keyword", "alias", "name"]
    values = list(registry.iter_match_values())
    for kind in wanted:
        for item in values:
            if item.get("value_type") == kind and item.get("raw_value"):
                chosen.append(str(item.get("raw_value")))
                break
    if not chosen and values:
        chosen.append(str(values[0].get("raw_value")))
    return "Telegram leak dump database panel log test metni: " + " ".join(chosen)

def main():
    files = [
        ROOT / "assets" / "assets.sample.json",
        ROOT / "assets" / "assets.local.json",
        ROOT / "core" / "masking.py",
        ROOT / "core" / "asset_registry.py",
        ROOT / "core" / "match_engine.py",
        ROOT / "run_asset_match_test.py",
        ROOT / "run_asset_scope_validate.py",
    ]
    py_files = [
        ROOT / "core" / "masking.py",
        ROOT / "core" / "asset_registry.py",
        ROOT / "core" / "match_engine.py",
        ROOT / "run_asset_match_test.py",
        ROOT / "run_asset_scope_validate.py",
    ]

    file_checks = [check_file(p) for p in files]
    compile_checks = [compile_python(p) for p in py_files]

    from core.masking import mask_text, mask_value
    from core.asset_registry import load_asset_registry
    from core.match_engine import scan_text

    masked_email = mask_value("sample.person@example.com", "email")
    masked_text = mask_text("mail sample.person@example.com tel +905551112233 token ABCD1234EFGH5678IJKL9012MNOP3456")

    registry = load_asset_registry()
    registry_summary = registry.summary()
    sample_text = build_registry_test_text(registry)
    scan_result = scan_text(sample_text, source_id="sprint2_health_check", source_type="health_check")
    summary = scan_result.get("summary", {})

    matches_dump = json.dumps(scan_result.get("matches", []), ensure_ascii=False)
    raw_email_not_leaked = "sample.person@example.com" not in matches_dump

    checks = []
    checks.append(("files_exist", all(item["exists"] for item in file_checks)))
    checks.append(("python_compile", all(item["ok"] for item in compile_checks)))
    checks.append(("mask_email", masked_email == "s****@example.com"))
    checks.append(("mask_text_no_raw_email", "sample.person@example.com" not in masked_text))
    checks.append(("registry_has_assets", int(registry_summary.get("asset_count", 0)) > 0))
    checks.append(("registry_has_match_values", int(registry_summary.get("match_value_count", 0)) > 0))
    checks.append(("match_engine_found_matches", int(summary.get("match_count", 0)) > 0))
    checks.append(("match_engine_masks_sample_email", raw_email_not_leaked))

    ok = all(v for _, v in checks)
    report = {
        "status": "ok" if ok else "fail",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "project": "PII Leak Radar",
        "sprint": "Sprint 2 - Asset Scope & Match Engine",
        "checks": [{"name": n, "ok": v} for n, v in checks],
        "files": file_checks,
        "compile": compile_checks,
        "registry_summary": registry_summary,
        "match_summary": summary,
    }
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    report_path = reports / "sprint2_health_check.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("SPRINT2_HEALTH_OK" if ok else "SPRINT2_HEALTH_FAIL")
    print("report=" + str(report_path))
    print("registry_mode=" + str(registry_summary.get("mode")))
    print("asset_count=" + str(registry_summary.get("asset_count")))
    print("match_value_count=" + str(registry_summary.get("match_value_count")))
    print("match_count=" + str(summary.get("match_count")))
    print("max_risk_score=" + str(summary.get("max_risk_score")))
    print("")
    print("Checks:")
    for name, value in checks:
        print("- " + name + "=" + str(value))
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())

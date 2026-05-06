import argparse
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
CONFIG = ROOT / "config"
PACKAGE_ROOT = REPORTS / "evidence_packages"

REPORT_CANDIDATES = [
    "dashboard.html",
    "full_pipeline_report.html",
    "full_pipeline_report.json",
    "health_check.html",
    "health_check.json",
    "source_registry_policy_validate_report.html",
    "source_registry_policy_validate_report.json",
    "safe_connectors_dry_run_report.html",
    "safe_connectors_dry_run_results.json",
    "source_catalog.html",
    "source_catalog.json",
    "paste_manual_review_report.html",
    "paste_manual_review_results.json",
    "asset_match_report.html",
    "asset_match_report.json",
]

CONFIG_CANDIDATES = [
    CONFIG / "scope.yml",
    CONFIG / "source_registry_policy.json",
    ROOT / "registry.yml",
    ROOT / "PROJECT_STATUS.md",
    ROOT / "PASTE_SOURCE_ONBOARDING.md",
]


def safe_name(value):
    text = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in str(value).strip())
    return text.strip("_") or "case"


def copy_if_exists(src, dest_dir):
    src = Path(src)
    if not src.exists() or not src.is_file():
        return None
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copy2(src, dest)
    return dest


def create_package(case, reports_root=REPORTS, config_root=CONFIG, output_root=PACKAGE_ROOT, project_root=ROOT):
    reports_root = Path(reports_root)
    config_root = Path(config_root)
    output_root = Path(output_root)
    project_root = Path(project_root)

    case_id = safe_name(case)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    package_dir = output_root / f"{case_id}_{stamp}"
    reports_dir = package_dir / "reports"
    config_dir = package_dir / "config_snapshot"

    config_candidates = [
        config_root / "scope.yml",
        config_root / "source_registry_policy.json",
        project_root / "registry.yml",
        project_root / "PROJECT_STATUS.md",
        project_root / "PASTE_SOURCE_ONBOARDING.md",
    ]

    copied = []
    for name in REPORT_CANDIDATES:
        copied_path = copy_if_exists(reports_root / name, reports_dir)
        if copied_path:
            copied.append(str(copied_path.relative_to(package_dir)))

    for src in config_candidates:
        copied_path = copy_if_exists(src, config_dir)
        if copied_path:
            copied.append(str(copied_path.relative_to(package_dir)))

    manifest = {
        "case_id": case_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "raw_sensitive_output": False,
        "package_dir": str(package_dir),
        "files": copied,
        "notes": [
            "Sanitized report/config snapshot package.",
            "Database files, raw inbox files, logs, and local assets are not included.",
        ],
    }

    package_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = package_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    zip_path = output_root / f"{case_id}_{stamp}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in package_dir.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(package_dir.parent))

    return {
        "case_id": case_id,
        "file_count": len(copied),
        "package_dir": package_dir,
        "manifest_path": manifest_path,
        "zip_path": zip_path,
    }


def main():
    parser = argparse.ArgumentParser(description="Create sanitized evidence package")
    parser.add_argument("--case", required=True, help="Case identifier")
    args = parser.parse_args()

    result = create_package(args.case)

    print("EVIDENCE_PACKAGE")
    print(f"case_id={result['case_id']}")
    print(f"file_count={result['file_count']}")
    print(f"package_dir={result['package_dir']}")
    print(f"zip={result['zip_path']}")
    print("raw_sensitive_output=False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

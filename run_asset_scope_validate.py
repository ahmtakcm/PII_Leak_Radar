import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.asset_registry import load_asset_registry
from core.reporting import build_report

LOCAL_PATH = ROOT / "assets" / "assets.local.json"
TEMPLATE_PATH = ROOT / "assets" / "assets.local.template.json"
REPORTS = ROOT / "reports"
REPORT_PATH = REPORTS / "asset_scope_validate_report.json"

ALLOWED_KINDS = {"person", "organization", "digital_identity", "domain", "custom_keyword", "custom"}
ALLOWED_SENSITIVITY = {"low", "medium", "high", "critical"}

LIST_FIELDS = {
    "aliases",
    "emails",
    "phones",
    "usernames",
    "domains",
    "subdomains",
    "profile_urls",
    "urls",
    "keywords",
}

PLACEHOLDER_MARKERS = [
    "PLACEHOLDER",
    "ORNEK",
    "ÖRNEK",
    "KISI_ADI",
    "KURUM_ADI",
    "DOMAIN_PLACEHOLDER",
    "CUSTOM_KEYWORD",
]

def load_json(path):
    if not path.exists():
        return None, "missing"
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(data, dict):
            return None, "root_not_object"
        return data, None
    except Exception as exc:
        return None, "json_error: " + str(exc)

def contains_placeholder(value):
    text = str(value or "").upper()
    return any(marker.upper() in text for marker in PLACEHOLDER_MARKERS)

def walk_values(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from walk_values(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk_values(v)
    else:
        yield value

def validate_assets(data):
    warnings = []
    errors = []
    duplicate_ids = []
    seen_ids = set()
    by_kind = {}
    by_sensitivity = {}
    enabled_count = 0
    disabled_count = 0
    placeholder_count = 0

    assets = data.get("assets", [])
    if not isinstance(assets, list):
        errors.append("assets_field_not_list")
        assets = []

    for index, asset in enumerate(assets):
        if not isinstance(asset, dict):
            errors.append("asset_not_object_at_index_" + str(index))
            continue

        asset_id = str(asset.get("asset_id", "")).strip()
        if not asset_id:
            errors.append("missing_asset_id_at_index_" + str(index))
        elif asset_id in seen_ids:
            duplicate_ids.append(asset_id)
        else:
            seen_ids.add(asset_id)

        kind = str(asset.get("asset_kind", "custom")).strip()
        sensitivity = str(asset.get("sensitivity", "medium")).strip().lower()

        if kind not in ALLOWED_KINDS:
            warnings.append("unknown_asset_kind:" + kind)

        if sensitivity not in ALLOWED_SENSITIVITY:
            warnings.append("unknown_sensitivity:" + sensitivity)

        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_sensitivity[sensitivity] = by_sensitivity.get(sensitivity, 0) + 1

        if asset.get("enabled") is False:
            disabled_count += 1
        else:
            enabled_count += 1

        for field in LIST_FIELDS:
            if field in asset and asset.get(field) is not None and not isinstance(asset.get(field), list):
                warnings.append("field_should_be_list:" + asset_id + ":" + field)

        for raw in walk_values(asset):
            if contains_placeholder(raw):
                placeholder_count += 1

    for dup in duplicate_ids:
        errors.append("duplicate_asset_id:" + dup)

    return {
        "asset_count": len(assets),
        "enabled_count": enabled_count,
        "disabled_count": disabled_count,
        "by_kind": by_kind,
        "by_sensitivity": by_sensitivity,
        "placeholder_count": placeholder_count,
        "warnings": warnings,
        "errors": errors,
    }

def main():
    print("ASSET_SCOPE_VALIDATE")

    REPORTS.mkdir(exist_ok=True)

    local_data, local_error = load_json(LOCAL_PATH)
    template_exists = TEMPLATE_PATH.exists()

    if local_error:
        result = {
            "status": "fail",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "reason": local_error,
            "local_file": str(LOCAL_PATH),
            "raw_values_printed": False,
        }
        REPORT_PATH.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print("status=fail")
        print("reason=" + local_error)
        print("raw_values_printed=False")
        return 1

    local_assets = local_data.get("assets", []) if isinstance(local_data, dict) else []
    local_asset_count = len(local_assets) if isinstance(local_assets, list) else 0

    validation = validate_assets(local_data)

    try:
        registry = load_asset_registry()
        summary = registry.summary()
    except Exception as exc:
        result = {
            "status": "fail",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "reason": "registry_error: " + str(exc),
            "local_file": str(LOCAL_PATH),
            "template_exists": template_exists,
            "local_validation": validation,
            "raw_values_printed": False,
        }
        REPORT_PATH.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print("status=fail")
        print("reason=registry_error")
        print("raw_values_printed=False")
        return 1

    has_errors = len(validation.get("errors", [])) > 0

    result = {
        "status": "fail" if has_errors else "ok",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "local_file": str(LOCAL_PATH),
        "template_file": str(TEMPLATE_PATH),
        "template_exists": template_exists,
        "local_asset_count": local_asset_count,
        "active_registry_source": summary.get("source_path"),
        "active_registry_mode": summary.get("mode"),
        "active_asset_count": summary.get("asset_count"),
        "active_match_value_count": summary.get("match_value_count"),
        "local_validation": validation,
        "raw_values_printed": False,
    }
    result["report_schema"] = build_report(
        "asset_scope_validate",
        summary={
            "local_asset_count": local_asset_count,
            "active_asset_count": summary.get("asset_count"),
            "active_match_value_count": summary.get("match_value_count"),
            "warning_count": len(validation.get("warnings", [])),
            "error_count": len(validation.get("errors", [])),
        },
        warnings=validation.get("warnings", []),
        errors=validation.get("errors", []),
        inputs={"local_file": str(LOCAL_PATH), "template_file": str(TEMPLATE_PATH)},
        outputs={"json": str(REPORT_PATH)},
        raw_sensitive_output=False,
    )

    REPORT_PATH.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print("status=" + result["status"])
    print("local_asset_count=" + str(local_asset_count))
    print("active_registry_source=" + str(summary.get("source_path")))
    print("active_registry_mode=" + str(summary.get("mode")))
    print("active_asset_count=" + str(summary.get("asset_count")))
    print("active_match_value_count=" + str(summary.get("match_value_count")))
    print("enabled_count=" + str(validation.get("enabled_count")))
    print("disabled_count=" + str(validation.get("disabled_count")))
    print("placeholder_count=" + str(validation.get("placeholder_count")))
    print("warning_count=" + str(len(validation.get("warnings", []))))
    print("error_count=" + str(len(validation.get("errors", []))))
    print("report=" + str(REPORT_PATH))
    print("raw_values_printed=False")

    if local_asset_count == 0:
        print("note=assets.local.json bos oldugu icin sistem sample assetleri kullaniyor.")
    else:
        print("note=assets.local.json dolu oldugu icin sistem local assetleri kullaniyor.")

    return 1 if has_errors else 0

if __name__ == "__main__":
    raise SystemExit(main())

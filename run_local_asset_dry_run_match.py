import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.asset_registry import load_asset_registry
from core.masking import mask_value
from core.match_engine import scan_text

REPORTS = ROOT / "reports"
REPORT_PATH = REPORTS / "local_asset_dry_run_match_report.json"

PREFERRED_TYPES = ["email", "phone", "domain", "username", "keyword", "alias", "name"]

def build_safe_test_text(registry):
    values = list(registry.iter_match_values())
    chosen = []

    for value_type in PREFERRED_TYPES:
        for item in values:
            if item.get("value_type") == value_type and item.get("raw_value"):
                chosen.append({
                    "value_type": value_type,
                    "raw_value": str(item.get("raw_value")),
                    "masked_value": mask_value(item.get("raw_value"), value_type),
                    "asset_id": item.get("asset_id"),
                })
                break

    if not chosen and values:
        item = values[0]
        value_type = str(item.get("value_type", "keyword"))
        chosen.append({
            "value_type": value_type,
            "raw_value": str(item.get("raw_value")),
            "masked_value": mask_value(item.get("raw_value"), value_type),
            "asset_id": item.get("asset_id"),
        })

    text_parts = ["Telegram leak dump database panel log dry-run test."]
    for item in chosen:
        text_parts.append(item["raw_value"])

    return " ".join(text_parts), chosen

def strip_raw_values_from_matches(matches):
    cleaned = []
    for match in matches:
        item = dict(match)
        # Match engine zaten raw_value dönmüyor; yine de ekstra güvenlik.
        item.pop("raw_value", None)
        item.pop("normalized_value", None)
        cleaned.append(item)
    return cleaned

def main():
    print("LOCAL_ASSET_DRY_RUN_MATCH")

    REPORTS.mkdir(exist_ok=True)

    registry = load_asset_registry()
    registry_summary = registry.summary()

    text, chosen = build_safe_test_text(registry)
    result = scan_text(
        text,
        source_id="local_asset_dry_run_match",
        source_type="local_asset_dry_run"
    )

    matches = strip_raw_values_from_matches(result.get("matches", []))
    summary = result.get("summary", {})

    report = {
        "status": "ok",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "registry_summary": registry_summary,
        "test_value_count": len(chosen),
        "test_values_masked": [
            {
                "asset_id": item.get("asset_id"),
                "value_type": item.get("value_type"),
                "masked_value": item.get("masked_value"),
            }
            for item in chosen
        ],
        "match_summary": summary,
        "matches": matches,
        "raw_values_printed": False,
    }

    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("status=ok")
    print("registry_mode=" + str(registry_summary.get("mode")))
    print("asset_count=" + str(registry_summary.get("asset_count")))
    print("match_value_count=" + str(registry_summary.get("match_value_count")))
    print("test_value_count=" + str(len(chosen)))
    print("match_count=" + str(summary.get("match_count", 0)))
    print("asset_match_count=" + str(summary.get("asset_count", 0)))
    print("max_risk_score=" + str(summary.get("max_risk_score", 0)))
    print("report=" + str(REPORT_PATH))
    print("raw_values_printed=False")

    if chosen:
        print("")
        print("Masked test values:")
        for item in chosen:
            print("- " + str(item.get("asset_id")) + " | " + str(item.get("value_type")) + " | " + str(item.get("masked_value")))

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

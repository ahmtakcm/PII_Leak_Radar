import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from adapters.cisa_kev_adapter import CisaKevAdapter
from adapters.nvd_adapter import NvdAdapter
from adapters.otx_adapter import OtxAdapter
from adapters.urlhaus_adapter import UrlhausAdapter
from core.reporting import build_report, write_json_report


FIXTURE_DIR = ROOT / "tests" / "fixtures" / "connectors"
REQUIRED_EVENT_FIELDS = ["source_id", "external_id", "type", "title", "severity"]


def parse_args():
    parser = argparse.ArgumentParser(description="Validate connector parser fixtures without network access")
    parser.add_argument("--fixture-dir", default=str(FIXTURE_DIR))
    return parser.parse_args()


def source_record(source_id, adapter, category, risk_base=50):
    return {
        "id": source_id,
        "name": source_id,
        "adapter": adapter,
        "category": category,
        "risk_base": risk_base,
        "limit": 10,
    }


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_events(source_id, events):
    errors = []
    if not events:
        errors.append(f"{source_id}: no events parsed")
        return errors

    for idx, event in enumerate(events):
        missing = [field for field in REQUIRED_EVENT_FIELDS if not event.get(field)]
        if missing:
            errors.append(f"{source_id}[{idx}]: missing fields: {','.join(missing)}")
    return errors


def run_fixture_suite(fixture_dir=FIXTURE_DIR):
    fixture_dir = Path(fixture_dir)
    cases = [
        {
            "source_id": "cisa_kev",
            "path": fixture_dir / "cisa_kev.json",
            "adapter": CisaKevAdapter(source_record("cisa_kev", "cisa_kev", "vulnerability_catalog", 85)),
            "parser": lambda adapter, path: adapter.parse_payload(load_json(path), 10),
        },
        {
            "source_id": "nvd_recent",
            "path": fixture_dir / "nvd_recent.json",
            "adapter": NvdAdapter(source_record("nvd_recent", "nvd", "vulnerability_database", 65)),
            "parser": lambda adapter, path: adapter.parse_payload(load_json(path), 10),
        },
        {
            "source_id": "urlhaus_recent",
            "path": fixture_dir / "urlhaus_recent.csv",
            "adapter": UrlhausAdapter(source_record("urlhaus_recent", "urlhaus", "malware_url_feed", 75)),
            "parser": lambda adapter, path: adapter.parse_text(Path(path).read_text(encoding="utf-8"), 10),
        },
        {
            "source_id": "otx_subscribed",
            "path": fixture_dir / "otx_subscribed.json",
            "adapter": OtxAdapter(source_record("otx_subscribed", "otx", "threat_intel_pulses", 70)),
            "parser": lambda adapter, path: adapter.parse_payload(load_json(path), 10),
        },
    ]

    results = []
    errors = []

    for case in cases:
        source_id = case["source_id"]
        path = case["path"]
        if not path.exists():
            errors.append(f"{source_id}: fixture missing: {path}")
            results.append({"source_id": source_id, "status": "error", "event_count": 0, "fixture": str(path)})
            continue

        try:
            events = case["parser"](case["adapter"], path)
            case_errors = validate_events(source_id, events)
        except Exception as exc:
            events = []
            case_errors = [f"{source_id}: {type(exc).__name__}: {exc}"]

        errors.extend(case_errors)
        results.append(
            {
                "source_id": source_id,
                "status": "error" if case_errors else "ok",
                "event_count": len(events),
                "fixture": str(path),
            }
        )

    return results, errors


def main():
    args = parse_args()
    results, errors = run_fixture_suite(args.fixture_dir)
    json_path = ROOT / "reports" / "connector_fixture_validate_report.json"
    report = build_report(
        name="connector_fixture_validate",
        summary={
            "fixture_count": len(results),
            "ok_count": sum(1 for item in results if item["status"] == "ok"),
            "error_count": len(errors),
        },
        errors=errors,
        outputs={"json": str(json_path)},
        data={"results": results},
    )
    write_json_report(json_path, report)

    print("CONNECTOR_FIXTURE_VALIDATE")
    print(f"status={report['status']}")
    print(f"fixture_count={report['summary']['fixture_count']}")
    print(f"ok_count={report['summary']['ok_count']}")
    print(f"error_count={report['summary']['error_count']}")
    print(f"json={json_path}")
    for error in errors:
        print(f"error={error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

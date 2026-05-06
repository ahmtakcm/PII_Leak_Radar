import hashlib
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.dashboard import write_dashboard
from core.dedup_store import DedupStore
from core.export_report import write_export_json, write_export_report
from core.indicator_extractor import extract_indicators
from core.sanitizer import mask_text, sanitized_copy
from parsers.export_parser import ExportParser


SUPPORTED_EXTENSIONS = {".json", ".html", ".htm", ".txt", ".log", ".csv"}


def main():
    inbox = ROOT / "exports_inbox"
    inbox.mkdir(parents=True, exist_ok=True)

    parser = ExportParser()
    store = DedupStore(ROOT / "data" / "pii_radar.db")

    files = [
        p for p in inbox.rglob("*")
        if p.is_file()
        and p.suffix.lower() in SUPPORTED_EXTENSIONS
        and not p.name.startswith("_")
    ]

    print("=== PII Leak Radar | Export Parser ===")
    print(f"inbox={inbox}")
    print(f"files={len(files)}")

    started = time.perf_counter()
    hits = []
    parsed_messages = 0
    new_hits = 0
    duplicate_hits = 0
    error_count = 0
    error_messages = []

    for path in files:
        print(f"[PARSE] {path.name}")

        try:
            messages = parser.parse_file(path)
        except Exception as exc:
            error_count += 1
            msg = f"{path.name}: {type(exc).__name__}: {exc}"
            error_messages.append(msg)
            print(f"[ERROR] {msg}")
            continue

        parsed_messages += len(messages)
        file_hit_count = 0

        for msg in messages:
            text = msg.get("text", "")
            indicators = extract_indicators(text)

            if indicators["indicator_count"] <= 0:
                continue

            event = build_event(msg, indicators)
            safe_event = sanitized_copy(event)

            is_new = store.add_observation(safe_event)
            if is_new:
                new_hits += 1
            else:
                duplicate_hits += 1

            hits.append(safe_event)
            file_hit_count += 1

        print(f"[OK] {path.name}: mesaj={len(messages)} bulgu={file_hit_count}")

    duration_ms = int((time.perf_counter() - started) * 1000)

    status = "ok" if error_count == 0 else "error"
    suggested_action = "Export bulguları manuel inceleme kuyruğunda değerlendirilmeli; ham hassas veri paylaşılmamalı."
    if len(files) == 0:
        suggested_action = "exports_inbox klasörüne kullanıcı tarafından sağlanan Telegram/Discord export dosyası eklenmeli."

    store.record_source_run(
        source_id="telegram_discord_exports",
        source_name="Telegram Discord Export Parser",
        status=status,
        fetched_count=parsed_messages,
        new_count=new_hits,
        duplicate_count=duplicate_hits,
        error_message=" | ".join(error_messages),
        suggested_action=suggested_action,
        duration_ms=duration_ms,
    )

    report_path = write_export_report(
        hits=hits,
        scanned_files=[str(p) for p in files],
        output_path=ROOT / "reports" / "export_parse_report.html",
    )
    json_path = write_export_json(
        hits=hits,
        output_path=ROOT / "reports" / "export_parse_results.json",
        scanned_files=[str(p) for p in files],
        errors=error_messages,
    )

    recent = store.recent_observations(limit=300)
    source_runs = store.latest_source_runs()
    dashboard_path = write_dashboard(
        recent,
        ROOT / "reports" / "dashboard.html",
        source_runs=source_runs,
    )

    store.close()

    print("")
    print("=== ÖZET ===")
    print(f"Taranan dosya: {len(files)}")
    print(f"Parse edilen mesaj/parça: {parsed_messages}")
    print(f"Bulgu: {len(hits)}")
    print(f"Yeni bulgu: {new_hits}")
    print(f"Duplicate bulgu: {duplicate_hits}")
    print(f"Hata: {error_count}")
    print(f"Export HTML rapor: {report_path}")
    print(f"Export JSON rapor: {json_path}")
    print(f"Unified dashboard: {dashboard_path}")
    print("")
    print("Not: Bu modül offline/user-provided export parser olarak çalışır; yetkisiz erişim yapmaz.")


def build_event(msg, indicators):
    text = msg.get("text", "")
    masked_snippet = mask_text(text[:600])

    indicator_types = indicators.get("indicator_types", [])
    title = "Export hit"
    if indicator_types:
        title += " | " + ", ".join(indicator_types[:5])

    external_raw = "|".join([
        str(msg.get("source_file_name", "")),
        str(msg.get("message_id", "")),
        str(indicator_types),
    ])
    external_id = hashlib.sha256(external_raw.encode("utf-8")).hexdigest()

    return {
        "source_id": "telegram_discord_exports",
        "source_name": "Telegram Discord Export Parser",
        "source_category": "export_parser",
        "legal_level": "user_provided_export_only",
        "review_priority": "manual_review",
        "external_id": external_id,
        "type": "export_message_indicator",
        "title": title,
        "platform": msg.get("platform", ""),
        "source_file_name": msg.get("source_file_name", ""),
        "timestamp": msg.get("timestamp", ""),
        "author": msg.get("author", ""),
        "indicator_types": indicator_types,
        "indicators": indicators.get("indicators", {}),
        "indicator_count": indicators.get("indicator_count", 0),
        "risk_score": indicators.get("risk_score", 0),
        "risk_label": indicators.get("risk_label", "low"),
        "recommended_action": indicators.get("recommended_action", ""),
        "masked_snippet": masked_snippet,
        "severity": indicators.get("risk_label", "low"),
    }


if __name__ == "__main__":
    main()

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from connectors.registry import ConnectorRegistry
from core.dashboard import write_dashboard
from core.dedup_store import DedupStore
from core.policy import recommended_action
from core.registry_loader import enabled_sources, load_registry
from core.risk_score import risk_label, score_event
from core.sanitizer import sanitized_copy


def parse_args():
    parser = argparse.ArgumentParser(description="PII Leak Radar source registry scan")
    parser.add_argument(
        "--with-network",
        action="store_true",
        help="Enable live public feed fetches. Default is offline metadata-only mode.",
    )
    return parser.parse_args()


def suggest_action(source_id, status, fetched_count, duplicate_count, error_message=""):
    if status == "skipped":
        return "Varsayilan offline mod. Canli public feed taramasi icin --with-network kullan."

    if status == "error":
        if "HTTP Error 403" in error_message or "HTTP Error 401" in error_message:
            return "API key / erisim yetkisi kontrol edilmeli."
        if "timed out" in error_message.lower():
            return "Ag baglantisi veya timeout degeri kontrol edilmeli."
        return "Adapter veya kaynak formati kontrol edilmeli."

    if fetched_count == 0:
        return "Kaynak bos dondu; endpoint veya filtre tarih araligi kontrol edilmeli."

    if fetched_count > 0 and duplicate_count >= fetched_count:
        return "Yeni kayit yok; tekrar taramada normal. Ilk taramaysa external_id/parser kontrol edilmeli."

    return "Normal takip."


def record_skipped(store, source_id, source_name, started, message):
    duration_ms = int((time.perf_counter() - started) * 1000)
    store.record_source_run(
        source_id=source_id,
        source_name=source_name,
        status="skipped",
        fetched_count=0,
        new_count=0,
        duplicate_count=0,
        error_message="",
        suggested_action=message,
        duration_ms=duration_ms,
    )


def main():
    args = parse_args()
    registry = load_registry(ROOT / "registry.yml")
    global_cfg = registry.get("global", {})
    registry_policy = registry.get("policy", {})

    timeout = int(global_cfg.get("default_timeout_seconds", 30))
    dry_run = bool(global_cfg.get("dry_run", True))
    alerts_enabled = bool(global_cfg.get("alerts_enabled", False))
    mask_sensitive = bool(global_cfg.get("mask_sensitive", True))

    print("=== PII Leak Radar | Source Registry Dry Run ===")
    print(
        f"dry_run={dry_run} alerts_enabled={alerts_enabled} "
        f"mask_sensitive={mask_sensitive} network_enabled={args.with_network}"
    )

    store = DedupStore(ROOT / "data" / "pii_radar.db")

    collected = []
    total_new_count = 0
    total_duplicate_count = 0
    error_count = 0
    skipped_count = 0

    for source in enabled_sources(registry):
        source_id = source.get("id")
        source_name = source.get("name", source_id)
        started = time.perf_counter()

        runtime_policy = {
            "network_enabled": bool(args.with_network),
            "auth_enabled": False,
            "credential_use_enabled": False,
            "manual_review_execution_enabled": False,
            "timeout": timeout,
        }

        connector = ConnectorRegistry.build(source, runtime_policy)
        if not connector:
            msg = f"connector yok: {source.get('adapter')}"
            print(f"[SKIP] {source_id}: {msg}")
            record_skipped(store, source_id, source_name, started, "Adapter mapping eklenmeli.")
            skipped_count += 1
            continue

        if not args.with_network:
            msg = "network_disabled_use_--with-network_for_live_fetch"
            print(f"[SKIP] {source_id}: {msg}")
            record_skipped(store, source_id, source_name, started, suggest_action(source_id, "skipped", 0, 0))
            skipped_count += 1
            continue

        block_reasons = connector.live_block_reasons()
        if block_reasons:
            msg = "policy_blocked:" + ",".join(block_reasons)
            print(f"[SKIP] {source_id}: {msg}")
            record_skipped(store, source_id, source_name, started, "Canli fetch policy tarafindan engellendi: " + ",".join(block_reasons))
            skipped_count += 1
            continue

        print(f"[FETCH] {source_id} / {connector.adapter_name}")

        source_new = 0
        source_duplicate = 0
        fetched_count = 0

        try:
            events = connector.fetch_live()
            fetched_count = len(events)
        except Exception as exc:
            error_count += 1
            error_message = f"{type(exc).__name__}: {exc}"
            duration_ms = int((time.perf_counter() - started) * 1000)

            print(f"[ERROR] {source_id}: {error_message}")
            store.record_source_run(
                source_id=source_id,
                source_name=source_name,
                status="error",
                fetched_count=0,
                new_count=0,
                duplicate_count=0,
                error_message=error_message,
                suggested_action=suggest_action(source_id, "error", 0, 0, error_message),
                duration_ms=duration_ms,
            )
            continue

        for event in events:
            event["legal_level"] = source.get("legal_level", "")
            event["review_priority"] = source.get("review_priority", "")
            event["risk_score"] = score_event(event)
            event["risk_label"] = risk_label(event["risk_score"])
            event["recommended_action"] = recommended_action(event, source, registry_policy)

            safe_event = sanitized_copy(event) if mask_sensitive else event
            is_new = store.add_observation(safe_event)

            if is_new:
                source_new += 1
                total_new_count += 1
            else:
                source_duplicate += 1
                total_duplicate_count += 1

            collected.append(safe_event)

        duration_ms = int((time.perf_counter() - started) * 1000)
        action = suggest_action(source_id, "ok", fetched_count, source_duplicate)

        store.record_source_run(
            source_id=source_id,
            source_name=source_name,
            status="ok",
            fetched_count=fetched_count,
            new_count=source_new,
            duplicate_count=source_duplicate,
            suggested_action=action,
            duration_ms=duration_ms,
        )

        print(f"[OK] {source_id}: {fetched_count} kayit islendi | yeni={source_new} duplicate={source_duplicate}")

    recent = store.recent_observations(limit=200)
    source_runs = store.latest_source_runs()
    dashboard_path = write_dashboard(
        recent,
        ROOT / "reports" / "dashboard.html",
        source_runs=source_runs,
    )

    out_json = ROOT / "reports" / "source_registry_dry_run.json"
    out_json.write_text(json.dumps(collected, ensure_ascii=False, indent=2), encoding="utf-8")

    store.close()

    print("")
    print("=== OZET ===")
    print(f"Toplam islenen: {len(collected)}")
    print(f"Yeni kayit: {total_new_count}")
    print(f"Duplicate: {total_duplicate_count}")
    print(f"Atlanan kaynak: {skipped_count}")
    print(f"Hata: {error_count}")
    print(f"JSON rapor: {out_json}")
    print(f"HTML dashboard: {dashboard_path}")
    print("")
    print("Not: Varsayilan mod offline-safe calisir; canli public feed icin --with-network kullan.")


if __name__ == "__main__":
    main()

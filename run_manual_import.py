import csv
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.dashboard import write_dashboard
from core.dedup_store import DedupStore
from core.indicator_extractor import extract_indicators
from core.manual_import_report import write_manual_import_html, write_manual_import_json
from core.sanitizer import mask_text, sanitized_copy


SUPPORTED_EXTENSIONS = {".csv", ".json", ".txt", ".log"}


CATEGORY_DEFAULTS = {
    "vendor_advisory": {
        "source_id": "vendor_advisories",
        "legal_level": "open_public_web",
        "risk_base": 55,
        "action": "Vendor advisory kurum ürün envanteriyle eşleştirilmeli; etkilenme varsa patch/mitigation takibi açılmalı.",
    },
    "breach_notification": {
        "source_id": "breach_notification_manual",
        "legal_level": "open_public_or_user_reported",
        "risk_base": 70,
        "action": "İhlal bildirimi doğrulanmalı; etkilenen varlık/kişi/veri tipi için olay kaydı ve bildirim süreci değerlendirilmeli.",
    },
    "paste_leak_review": {
        "source_id": "paste_leak_manual_review",
        "legal_level": "manual_review_required",
        "risk_base": 80,
        "action": "Paste/leak göstergesi manuel incelemeye alınmalı; credential denenmemeli, ham hassas veri yayılmamalı, delil hash'i korunmalı.",
    },
    "manual_review": {
        "source_id": "manual_osint_sources",
        "legal_level": "manual_review_required",
        "risk_base": 45,
        "action": "Manuel OSINT kaydı kapsam ve güvenilirlik açısından incelenmeli.",
    },
    "high_risk_intel": {
        "source_id": "high_risk_darkweb_intel_placeholder",
        "legal_level": "high_risk_manual_legal_review_required",
        "risk_base": 90,
        "action": "Yüksek riskli kaynak göstergesi. Aktif katılım/erişim yapılmadan yalnızca yasal/izinli rapor, üçüncü taraf istihbarat veya kullanıcı sağladığı delil üzerinden işlem yapılmalı.",
    },
}


def main():
    inbox = ROOT / "manual_sources_inbox"
    inbox.mkdir(parents=True, exist_ok=True)

    files = [
        p for p in inbox.rglob("*")
        if p.is_file()
        and p.suffix.lower() in SUPPORTED_EXTENSIONS
        and not p.name.startswith("_")
        and "_templates" not in str(p)
    ]

    print("=== PII Leak Radar | Manual Source Import ===")
    print(f"inbox={inbox}")
    print(f"files={len(files)}")

    store = DedupStore(ROOT / "data" / "pii_radar.db")

    started = time.perf_counter()
    imported_events = []
    parsed_rows = 0
    new_count = 0
    duplicate_count = 0
    error_count = 0
    error_messages = []

    for path in files:
        print(f"[IMPORT] {path.name}")

        try:
            rows = parse_file(path)
        except Exception as exc:
            error_count += 1
            msg = f"{path.name}: {type(exc).__name__}: {exc}"
            error_messages.append(msg)
            print(f"[ERROR] {msg}")
            continue

        parsed_rows += len(rows)
        file_hits = 0

        for row in rows:
            event = build_event(row, path)
            safe_event = sanitized_copy(event)

            is_new = store.add_observation(safe_event)
            if is_new:
                new_count += 1
            else:
                duplicate_count += 1

            imported_events.append(safe_event)
            file_hits += 1

        print(f"[OK] {path.name}: kayıt={len(rows)} import={file_hits}")

    duration_ms = int((time.perf_counter() - started) * 1000)

    suggested_action = "Manuel kaynak bulguları inceleme kuyruğunda değerlendirilmeli; ham hassas veri paylaşılmamalı."
    if len(files) == 0:
        suggested_action = "manual_sources_inbox klasörüne CSV/JSON/TXT manuel kaynak dosyası eklenmeli."

    status = "ok" if error_count == 0 else "error"

    store.record_source_run(
        source_id="manual_source_import",
        source_name="Manual Source Import",
        status=status,
        fetched_count=parsed_rows,
        new_count=new_count,
        duplicate_count=duplicate_count,
        error_message=" | ".join(error_messages),
        suggested_action=suggested_action,
        duration_ms=duration_ms,
    )

    html_path = write_manual_import_html(
        imported_events,
        [str(p) for p in files],
        ROOT / "reports" / "manual_import_report.html",
    )
    json_path = write_manual_import_json(
        imported_events,
        ROOT / "reports" / "manual_import_results.json",
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
    print(f"Parse edilen kayıt: {parsed_rows}")
    print(f"Import edilen bulgu: {len(imported_events)}")
    print(f"Yeni: {new_count}")
    print(f"Duplicate: {duplicate_count}")
    print(f"Hata: {error_count}")
    print(f"Manual import HTML: {html_path}")
    print(f"Manual import JSON: {json_path}")
    print(f"Unified dashboard: {dashboard_path}")
    print("")
    print("Not: Bu modül manuel/offline import yapar; yetkisiz erişim veya credential kullanımı yapmaz.")


def parse_file(path: Path) -> List[Dict[str, Any]]:
    suffix = path.suffix.lower()

    if suffix == ".csv":
        return parse_csv(path)
    if suffix == ".json":
        return parse_json(path)
    if suffix in (".txt", ".log"):
        return parse_text(path)

    return []


def parse_csv(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    rows = []

    reader = csv.DictReader(text.splitlines())
    for row in reader:
        clean = {str(k).strip(): ("" if v is None else str(v).strip()) for k, v in row.items() if k}
        if any(clean.values()):
            rows.append(clean)

    return rows


def parse_json(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))

    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if isinstance(data, dict):
        for key in ("records", "items", "sources", "events", "data"):
            val = data.get(key)
            if isinstance(val, list):
                return [x for x in val if isinstance(x, dict)]
        return [data]

    return []


def parse_text(path: Path) -> List[Dict[str, Any]]:
    content = path.read_text(encoding="utf-8", errors="replace")
    chunks = [c.strip() for c in content.split("\n\n") if c.strip()]

    rows = []
    for idx, chunk in enumerate(chunks):
        rows.append({
            "source_id": "manual_osint_sources",
            "category": "manual_review",
            "title": f"{path.name} manual note #{idx + 1}",
            "url": "",
            "observed_at": "",
            "legal_level": "manual_review_required",
            "risk_base": "45",
            "evidence_ref": path.name,
            "notes": chunk,
        })

    return rows


def build_event(row: Dict[str, Any], path: Path) -> Dict[str, Any]:
    category = (row.get("category") or "manual_review").strip()
    defaults = CATEGORY_DEFAULTS.get(category, CATEGORY_DEFAULTS["manual_review"])

    source_id = (row.get("source_id") or defaults["source_id"]).strip()
    title = (row.get("title") or "Manual source record").strip()
    url = (row.get("url") or "").strip()
    observed_at = (row.get("observed_at") or row.get("date") or "").strip()
    legal_level = (row.get("legal_level") or defaults["legal_level"]).strip()
    evidence_ref = (row.get("evidence_ref") or row.get("case_ref") or "").strip()
    notes = (row.get("notes") or row.get("description") or row.get("summary") or "").strip()

    try:
        risk_base = int(row.get("risk_base") or defaults["risk_base"])
    except Exception:
        risk_base = int(defaults["risk_base"])

    combined_text = "\n".join([title, url, observed_at, evidence_ref, notes])
    indicators = extract_indicators(combined_text)

    indicator_score = int(indicators.get("risk_score", 0) or 0)
    risk_score = max(risk_base, indicator_score)
    risk_label = label(risk_score)

    external_id = row.get("external_id") or stable_id(source_id, title, url, evidence_ref, notes)

    recommended_action = build_action(
        category=category,
        defaults=defaults,
        indicators=indicators,
        legal_level=legal_level,
    )

    return {
        "source_id": source_id,
        "source_name": "Manual Source Import",
        "source_category": category,
        "category": category,
        "legal_level": legal_level,
        "review_priority": row.get("review_priority") or "manual_review",
        "external_id": external_id,
        "type": "manual_source_record",
        "title": title,
        "url": url,
        "observed_at": observed_at,
        "evidence_ref": evidence_ref,
        "origin_file": path.name,
        "risk_base": risk_base,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "severity": risk_label,
        "indicator_types": indicators.get("indicator_types", []),
        "indicators": indicators.get("indicators", {}),
        "indicator_count": indicators.get("indicator_count", 0),
        "recommended_action": recommended_action,
        "masked_snippet": mask_text(combined_text[:700]),
        "notes_masked": mask_text(notes[:1200]),
    }


def build_action(category: str, defaults: Dict[str, Any], indicators: Dict[str, Any], legal_level: str) -> str:
    parts = [defaults.get("action", "")]

    indicator_action = indicators.get("recommended_action")
    if indicator_action:
        parts.append(indicator_action)

    if "high_risk" in str(legal_level) or category == "high_risk_intel":
        parts.append("Kısa yasal uyarı: Bu kaynak tipi yüksek risklidir; aktif erişim/katılım yerine delil muhafazası, raporlama ve yetkili inceleme akışı kullanılmalı.")

    return dedupe_sentences(parts)


def label(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def stable_id(*parts) -> str:
    raw = "|".join(str(p or "") for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def dedupe_sentences(parts: List[str]) -> str:
    seen = set()
    result = []

    for part in parts:
        clean = str(part).strip()
        if not clean:
            continue

        key = clean.lower()
        if key in seen:
            continue

        seen.add(key)
        result.append(clean)

    return " ".join(result)


if __name__ == "__main__":
    main()

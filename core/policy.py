from typing import Dict, Any


def recommended_action(event: Dict[str, Any], source: Dict[str, Any], registry_policy: Dict[str, Any] = None) -> str:
    registry_policy = registry_policy or {}
    action_by_risk = registry_policy.get("action_by_risk", {})

    event_type = str(event.get("type", "")).lower()
    source_category = str(event.get("source_category", "")).lower()
    risk_label = str(event.get("risk_label", "")).lower()
    source_action = str(source.get("suggested_action", "")).strip()

    if event_type == "config_notice":
        return "Konfigürasyon kontrolü gerekli. API anahtarı yoksa kaynak pasif/config notice olarak takip edilir."

    actions = []

    if source_action:
        actions.append(source_action)

    cve = event.get("cve")
    if cve and risk_label in ("critical", "high"):
        actions.append("CVE kurum envanterinde kullanılan ürünlerle eşleştirilmeli; eşleşme varsa patch/mitigation planı açılmalı.")

    ransomware_flag = str(event.get("known_ransomware_campaign_use", "")).lower()
    if ransomware_flag in ("known", "yes", "true"):
        actions.append("Ransomware kampanya kullanımı işaretli; acil triage, log korelasyonu ve etki analizi yapılmalı.")

    if source_category == "malware_url_feed":
        actions.append("URL/domain IOC olarak DNS, proxy, firewall ve EDR loglarında aranmalı; temas varsa olay kaydı oluşturulmalı.")

    if source_category == "threat_intel_pulses":
        actions.append("Pulse içindeki IOC'ler izinli telemetry üzerinde korele edilmeli; false positive için kaynak güvenilirliği kontrol edilmeli.")

    if source_category == "vulnerability_catalog":
        actions.append("Bilinen istismar kaydı olduğu için asset match varsa öncelik yüksek tutulmalı.")

    if not actions:
        default_action = action_by_risk.get(risk_label)
        if default_action:
            actions.append(default_action)
        else:
            actions.append("İzleme listesine al; kaynak güvenilirliği ve tekrar görülme sıklığını takip et.")

    return _dedupe_sentence(actions)


def _dedupe_sentence(parts):
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

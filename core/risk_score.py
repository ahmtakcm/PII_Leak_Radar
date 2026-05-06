from typing import Dict, Any


def score_event(event: Dict[str, Any]) -> int:
    base = int(event.get("risk_base", 40) or 40)
    source_type = event.get("source_category", "")
    severity = str(event.get("severity", "")).lower()
    cvss = event.get("cvss")

    score = base

    if source_type == "vulnerability_catalog":
        score += 10
    if source_type == "malware_url_feed":
        score += 8
    if source_type == "threat_intel_pulses":
        score += 5

    if severity in ("critical", "high"):
        score += 15
    elif severity == "medium":
        score += 8

    try:
        if cvss is not None:
            cvss_f = float(cvss)
            if cvss_f >= 9:
                score += 15
            elif cvss_f >= 7:
                score += 10
            elif cvss_f >= 4:
                score += 5
    except Exception:
        pass

    return max(0, min(100, score))


def risk_label(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"

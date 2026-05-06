import re
from typing import Dict, Any, List


URL_RE = re.compile(r"\bhttps?://[^\s<>'\"]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|tr|ru|cn|info|biz|xyz|top|site|online|shop|dev|app|gov|edu)\b", re.IGNORECASE)
TR_PHONE_RE = re.compile(r"(?<!\d)(?:\+?90\s*)?5\d{2}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)")
TC_CANDIDATE_RE = re.compile(r"(?<!\d)\d{11}(?!\d)")

CREDENTIAL_KEYWORDS = [
    "password", "passwd", "pass:", "pwd", "login:", "user:", "username",
    "credential", "combo", "combo list", "stealer", "cookie", "session",
    "token", "api_key", "apikey", "authorization", "bearer", "dump",
]

LEAK_KEYWORDS = [
    "leak", "leaked", "breach", "database", "db dump", "dumped",
    "satılık", "satilik", "sızıntı", "sizinti", "veri tabanı",
    "market", "panel", "log", "logs", "fresh logs", "fullz",
]

ILLEGAL_SOURCE_KEYWORDS = [
    "illegal market", "dark market", "black market", "carding",
    "cvv", "cc dump", "davet", "invite", "checker", "bot panel",
]


def extract_indicators(text: str) -> Dict[str, Any]:
    text = text or ""

    urls = _unique(URL_RE.findall(text))
    emails = _unique(EMAIL_RE.findall(text))
    ips = _unique(IPV4_RE.findall(text))
    cves = _unique([x.upper() for x in CVE_RE.findall(text)])
    domains = _unique([d for d in DOMAIN_RE.findall(text) if not _domain_inside_url(d, urls)])
    phones = _unique(TR_PHONE_RE.findall(text))
    tckn = _unique([x for x in TC_CANDIDATE_RE.findall(text) if _valid_tckn(x)])

    low = text.lower()

    credential_hits = [kw for kw in CREDENTIAL_KEYWORDS if kw in low]
    leak_hits = [kw for kw in LEAK_KEYWORDS if kw in low]
    illegal_source_hits = [kw for kw in ILLEGAL_SOURCE_KEYWORDS if kw in low]

    indicator_types = []
    values = {
        "urls": urls,
        "emails": emails,
        "ips": ips,
        "domains": domains,
        "cves": cves,
        "phones": phones,
        "tckn": tckn,
        "credential_keywords": credential_hits,
        "leak_keywords": leak_hits,
        "illegal_source_keywords": illegal_source_hits,
    }

    for key, val in values.items():
        if val:
            indicator_types.append(key)

    risk_score = _score(values)
    risk_label = _label(risk_score)

    return {
        "indicator_types": indicator_types,
        "indicators": values,
        "indicator_count": sum(len(v) for v in values.values()),
        "risk_score": risk_score,
        "risk_label": risk_label,
        "recommended_action": _recommended_action(values, risk_label),
    }


def _score(values: Dict[str, List[str]]) -> int:
    score = 0

    if values.get("tckn"):
        score += 45
    if values.get("credential_keywords"):
        score += 40
    if values.get("emails"):
        score += 20
    if values.get("phones"):
        score += 20
    if values.get("leak_keywords"):
        score += 25
    if values.get("illegal_source_keywords"):
        score += 25
    if values.get("urls"):
        score += 15
    if values.get("domains"):
        score += 10
    if values.get("ips"):
        score += 10
    if values.get("cves"):
        score += 20

    return max(0, min(100, score))


def _label(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _recommended_action(values: Dict[str, List[str]], risk_label: str) -> str:
    actions = []

    if values.get("tckn") or values.get("phones") or values.get("emails"):
        actions.append("PII sinyali var; ham veri paylaşılmadan maskeleme, delil hash'i ve yetkili inceleme kuyruğu kullanılmalı.")

    if values.get("credential_keywords"):
        actions.append("Credential/leak göstergesi var; credential denenmeden yalnızca kurum varlığı eşleştirmesi ve bildirim süreci işletilmeli.")

    if values.get("urls") or values.get("domains") or values.get("ips"):
        actions.append("IOC sinyali var; DNS/proxy/firewall/EDR loglarında izinli korelasyon yapılmalı.")

    if values.get("cves"):
        actions.append("CVE sinyali var; kurum envanteriyle eşleştirilmeli ve patch/mitigation önceliği değerlendirilmeli.")

    if values.get("illegal_source_keywords"):
        actions.append("Riskli/illegal kaynak göstergesi var; aktif katılım veya erişim yapılmadan yalnızca raporlama ve delil muhafazası yapılmalı.")

    if not actions:
        actions.append("Düşük riskli kayıt; izleme listesinde tutulabilir.")

    return " ".join(actions)


def _valid_tckn(value: str) -> bool:
    if not value.isdigit() or len(value) != 11:
        return False
    if value[0] == "0":
        return False

    digits = [int(x) for x in value]
    d10 = ((sum(digits[0:9:2]) * 7) - sum(digits[1:8:2])) % 10
    d11 = sum(digits[:10]) % 10

    return digits[9] == d10 and digits[10] == d11


def _unique(items: List[str]) -> List[str]:
    seen = set()
    result = []

    for item in items:
        clean = str(item).strip()
        if not clean:
            continue

        key = clean.lower()
        if key in seen:
            continue

        seen.add(key)
        result.append(clean)

    return result


def _domain_inside_url(domain: str, urls: List[str]) -> bool:
    domain_low = domain.lower()
    return any(domain_low in url.lower() for url in urls)

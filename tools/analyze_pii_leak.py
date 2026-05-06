# -*- coding: utf-8 -*-
"""
PII Leak Radar - Yerel ve güvenli ön inceleme aracı

Amaç:
- input klasöründeki txt/json/csv/log/md/html dosyalarını inceler.
- TC/GSM/e-posta/IBAN benzeri kişisel verileri maskeler.
- Riskli ifade kategorilerini sınıflandırır.
- CSV ve Markdown rapor üretir.
- Orijinal dosyaların SHA256 hash değerlerini çıkarır.

Bu araç:
- İnternete bağlanmaz.
- Telegram/Discord kanal aramaz.
- Bot/panel sorgusu yapmaz.
- Yetkisiz kişisel veri çekmez.
"""

import csv
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
REPORTS_DIR = BASE_DIR / "reports"
EVIDENCE_DIR = BASE_DIR / "evidence"

OUTPUT_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)
EVIDENCE_DIR.mkdir(exist_ok=True)

SUPPORTED_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".md", ".html", ".htm"
}


RISK_RULES = [
    {
        "category": "tc_kimlik_sorgu_iddiasi",
        "score": 60,
        "patterns": [
            r"\btc\b.*\bsorgu",
            r"\bt\.?c\.?\b.*\bkimlik",
            r"\bkimlik\b.*\bsorgu",
            r"\bmernis\b",
            r"\bnvi\b",
        ],
    },
    {
        "category": "gsm_sorgu_iddiasi",
        "score": 65,
        "patterns": [
            r"\bgsm\b.*\bsorgu",
            r"\btelefon\b.*\bsorgu",
            r"\bnumara\b.*\bkimlik",
            r"\bnumaradan\b.*\bbul",
            r"\bgsm\b.*\btc",
        ],
    },
    {
        "category": "adres_aile_bilgisi_iddiasi",
        "score": 70,
        "patterns": [
            r"\badres\b.*\bsorgu",
            r"\bikamet",
            r"\baile\b.*\bsorgu",
            r"\bsoy\s*ağacı",
            r"\btapu\b.*\bsorgu",
        ],
    },
    {
        "category": "panel_satis_reklami",
        "score": 75,
        "patterns": [
            r"\bpanel\b",
            r"\bsorgu\s*panel",
            r"\büyelik\b",
            r"\bkontör\b",
            r"\bpaket\b.*\bsorgu",
            r"\bapi\b.*\bsorgu",
        ],
    },
    {
        "category": "bot_kanal_grup_reklami",
        "score": 55,
        "patterns": [
            r"\bbot\b",
            r"\btelegram\b",
            r"\bdiscord\b",
            r"\bkanal\b",
            r"\bgrup\b",
        ],
    },
    {
        "category": "odeme_ve_satis_izi",
        "score": 85,
        "patterns": [
            r"\biban\b",
            r"\bpapara\b",
            r"\busdt\b",
            r"\bbtc\b",
            r"\btrx\b",
            r"\bcrypto\b",
            r"\bkripto\b",
            r"\bödeme\b",
            r"\bfiyat\b",
        ],
    },
]


TC_REGEX = re.compile(r"(?<!\d)([1-9]\d{10})(?!\d)")
PHONE_REGEX = re.compile(
    r"(?<!\d)(?:\+?90[\s\-.]*)?(?:0[\s\-.]*)?5(?:[\s\-.]*\d){9}(?!\d)"
)
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)
IBAN_REGEX = re.compile(
    r"\bTR[\s\-]?\d{2}(?:[\s\-]?\d{4}){5}(?:[\s\-]?\d{2})?\b",
    re.IGNORECASE,
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_valid_tckn(value: str) -> bool:
    if not re.fullmatch(r"[1-9]\d{10}", value):
        return False

    digits = [int(x) for x in value]

    if digits[0] == 0:
        return False

    rule_10 = ((sum(digits[0:9:2]) * 7) - sum(digits[1:8:2])) % 10
    rule_11 = sum(digits[:10]) % 10

    return digits[9] == rule_10 and digits[10] == rule_11


def mask_tc(value: str) -> str:
    return value[:2] + "*******" + value[-2:]


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)

    if digits.startswith("90") and len(digits) == 12:
        digits = "0" + digits[2:]

    if digits.startswith("5") and len(digits) == 10:
        digits = "0" + digits

    return digits


def mask_phone(value: str) -> str:
    digits = normalize_phone(value)

    if len(digits) == 11 and digits.startswith("05"):
        return digits[:2] + "********" + digits[-2:]

    return "[GSM_MASKELENDI]"


def mask_email(value: str) -> str:
    try:
        local, domain = value.split("@", 1)
        if len(local) <= 2:
            masked_local = local[0] + "***"
        else:
            masked_local = local[0] + "***" + local[-1]
        return masked_local + "@" + domain
    except Exception:
        return "[EMAIL_MASKELENDI]"


def mask_iban(value: str) -> str:
    compact = re.sub(r"\s|-", "", value).upper()
    if len(compact) >= 10:
        return compact[:4] + "***************" + compact[-4:]
    return "[IBAN_MASKELENDI]"


def mask_text(text: str):
    counts = {
        "tc": 0,
        "gsm": 0,
        "email": 0,
        "iban": 0,
    }

    def tc_replacer(match):
        value = match.group(1)
        if is_valid_tckn(value):
            counts["tc"] += 1
            return mask_tc(value)
        return value

    def phone_replacer(match):
        value = match.group(0)
        digits = normalize_phone(value)
        if len(digits) == 11 and digits.startswith("05"):
            counts["gsm"] += 1
            return mask_phone(value)
        return value

    def email_replacer(match):
        counts["email"] += 1
        return mask_email(match.group(0))

    def iban_replacer(match):
        counts["iban"] += 1
        return mask_iban(match.group(0))

    masked = TC_REGEX.sub(tc_replacer, text)
    masked = PHONE_REGEX.sub(phone_replacer, masked)
    masked = EMAIL_REGEX.sub(email_replacer, masked)
    masked = IBAN_REGEX.sub(iban_replacer, masked)

    return masked, counts


def normalize_text_for_match(text: str) -> str:
    return text.casefold()


def classify_risk(text: str, pii_counts: dict):
    normalized = normalize_text_for_match(text)

    categories = []
    score = 0
    matched_patterns = []

    for rule in RISK_RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, normalized, flags=re.IGNORECASE):
                categories.append(rule["category"])
                matched_patterns.append(pattern)
                score = max(score, rule["score"])
                break

    pii_total = sum(pii_counts.values())

    if pii_total > 0:
        categories.append("kisisel_veri_izi_maskelendi")
        score = max(score, 80)

    if pii_counts.get("tc", 0) > 0 and pii_counts.get("gsm", 0) > 0:
        categories.append("tc_gsm_birlikte")
        score = max(score, 95)

    if "panel_satis_reklami" in categories and "odeme_ve_satis_izi" in categories:
        categories.append("satis_odeme_birlikte")
        score = max(score, 90)

    if "gsm_sorgu_iddiasi" in categories and "tc_kimlik_sorgu_iddiasi" in categories:
        categories.append("gsm_tc_sorgu_iddiasi_birlikte")
        score = max(score, 92)

    score = min(score, 100)

    return sorted(set(categories)), score, matched_patterns


def text_from_telegram_text_field(value):
    if isinstance(value, str):
        return value

    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("text", "")))
        return " ".join(parts)

    return str(value) if value is not None else ""


def iter_json_records(path: Path):
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as f:
            data = json.load(f)
    except Exception:
        return

    if isinstance(data, dict) and isinstance(data.get("messages"), list):
        for idx, msg in enumerate(data["messages"], start=1):
            if not isinstance(msg, dict):
                continue

            text = text_from_telegram_text_field(msg.get("text", ""))
            sender = (
                msg.get("from")
                or msg.get("actor")
                or msg.get("author")
                or msg.get("sender")
                or ""
            )
            date = msg.get("date") or msg.get("timestamp") or ""

            if text.strip():
                yield {
                    "line_no": idx,
                    "date": date,
                    "sender": str(sender),
                    "text": text,
                }
        return

    # Genel JSON fallback: tüm string alanları kontrollü şekilde gez
    collected = []

    def walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{prefix}[{i}]")
        elif isinstance(obj, str):
            if obj.strip():
                collected.append((prefix, obj))

    walk(data)

    for idx, item in enumerate(collected, start=1):
        key, text = item
        yield {
            "line_no": idx,
            "date": "",
            "sender": key,
            "text": text,
        }


def iter_text_records(path: Path):
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            text = line.strip()
            if not text:
                continue

            yield {
                "line_no": idx,
                "date": "",
                "sender": "",
                "text": text,
            }


def iter_file_records(path: Path):
    if path.suffix.lower() == ".json":
        yield from iter_json_records(path)
    else:
        yield from iter_text_records(path)


def short_snippet(text: str, limit: int = 280) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def severity_label(score: int) -> str:
    if score >= 90:
        return "KRITIK"
    if score >= 75:
        return "YUKSEK"
    if score >= 50:
        return "ORTA"
    if score > 0:
        return "DUSUK"
    return "YOK"


def main():
    run_time = datetime.now().astimezone().isoformat(timespec="seconds")

    input_files = [
        p for p in INPUT_DIR.iterdir()
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS
    ]

    findings = []
    hashes = []

    for path in sorted(input_files):
        file_hash = sha256_file(path)
        hashes.append({
            "file": str(path.relative_to(BASE_DIR)),
            "sha256": file_hash,
            "size_bytes": path.stat().st_size,
        })

        for record in iter_file_records(path):
            raw_text = record["text"]
            masked_text, pii_counts = mask_text(raw_text)
            categories, score, matched_patterns = classify_risk(raw_text, pii_counts)

            if score <= 0:
                continue

            masked_sender, _ = mask_text(record.get("sender", ""))

            findings.append({
                "file": str(path.relative_to(BASE_DIR)),
                "line_no": record.get("line_no", ""),
                "date": record.get("date", ""),
                "sender_masked": masked_sender,
                "severity": severity_label(score),
                "risk_score": score,
                "categories": "; ".join(categories),
                "pii_tc_count": pii_counts.get("tc", 0),
                "pii_gsm_count": pii_counts.get("gsm", 0),
                "pii_email_count": pii_counts.get("email", 0),
                "pii_iban_count": pii_counts.get("iban", 0),
                "snippet_masked": short_snippet(masked_text),
                "matched_patterns": "; ".join(matched_patterns),
            })

    findings_csv = OUTPUT_DIR / "masked_findings.csv"
    hashes_json = OUTPUT_DIR / "evidence_hashes.json"
    report_md = REPORTS_DIR / "pii_leak_report.md"

    with findings_csv.open("w", encoding="utf-8-sig", newline="") as f:
        fieldnames = [
            "file",
            "line_no",
            "date",
            "sender_masked",
            "severity",
            "risk_score",
            "categories",
            "pii_tc_count",
            "pii_gsm_count",
            "pii_email_count",
            "pii_iban_count",
            "snippet_masked",
            "matched_patterns",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    with hashes_json.open("w", encoding="utf-8") as f:
        json.dump({
            "generated_at": run_time,
            "base_dir": str(BASE_DIR),
            "files": hashes,
        }, f, ensure_ascii=False, indent=2)

    total = len(findings)
    critical = sum(1 for x in findings if x["severity"] == "KRITIK")
    high = sum(1 for x in findings if x["severity"] == "YUKSEK")
    medium = sum(1 for x in findings if x["severity"] == "ORTA")

    top_findings = sorted(
        findings,
        key=lambda x: int(x["risk_score"]),
        reverse=True
    )[:20]

    report_lines = []
    report_lines.append("# PII Leak Radar Ön İnceleme Raporu")
    report_lines.append("")
    report_lines.append(f"- Üretim zamanı: `{run_time}`")
    report_lines.append(f"- İncelenen dosya sayısı: `{len(input_files)}`")
    report_lines.append(f"- Toplam bulgu: `{total}`")
    report_lines.append(f"- Kritik bulgu: `{critical}`")
    report_lines.append(f"- Yüksek bulgu: `{high}`")
    report_lines.append(f"- Orta bulgu: `{medium}`")
    report_lines.append("")
    report_lines.append("## Çıktılar")
    report_lines.append("")
    report_lines.append("- `output/masked_findings.csv`")
    report_lines.append("- `output/evidence_hashes.json`")
    report_lines.append("- `reports/pii_leak_report.md`")
    report_lines.append("")
    report_lines.append("## En yüksek riskli ilk bulgular")
    report_lines.append("")

    if not top_findings:
        report_lines.append("Riskli bulgu tespit edilmedi.")
    else:
        for idx, item in enumerate(top_findings, start=1):
            report_lines.append(f"### Bulgu {idx}")
            report_lines.append("")
            report_lines.append(f"- Dosya: `{item['file']}`")
            report_lines.append(f"- Satır/Kayıt: `{item['line_no']}`")
            report_lines.append(f"- Tarih: `{item['date']}`")
            report_lines.append(f"- Şiddet: `{item['severity']}`")
            report_lines.append(f"- Risk puanı: `{item['risk_score']}/100`")
            report_lines.append(f"- Kategoriler: `{item['categories']}`")
            report_lines.append(f"- Maskelenmiş özet: `{item['snippet_masked']}`")
            report_lines.append("")

    report_lines.append("## Not")
    report_lines.append("")
    report_lines.append(
        "Bu rapor, kişisel verileri maskeleyerek ön inceleme üretir. "
        "Yetkisiz sorgu, bot/panel kullanımı veya kişisel veri elde etme amacı taşımaz."
    )

    report_md.write_text("\n".join(report_lines), encoding="utf-8")

    print("PII Leak Radar tamamlandi.")
    print(f"Incelenen dosya sayisi: {len(input_files)}")
    print(f"Toplam bulgu: {total}")
    print(f"CSV: {findings_csv}")
    print(f"Rapor: {report_md}")
    print(f"Hash: {hashes_json}")


if __name__ == "__main__":
    main()

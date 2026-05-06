# -*- coding: utf-8 -*-
"""
PII Leak Radar - Genel İçerik Arama

Amaç:
- Proje klasörleri içinde güvenli, yerel arama yapmak.
- Eşleşen satırları PII maskelenmiş şekilde raporlamak.
- Markdown ve CSV çıktı üretmek.

Bu araç:
- İnternete bağlanmaz.
- Telegram/Discord kanal aramaz.
- Bot/panel sorgusu yapmaz.
- Yalnızca yerel proje klasörlerinde arama yapar.
"""

import argparse
import csv
import json
import os
import re
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]

DEFAULT_FOLDERS = [
    "input",
    "evidence",
    "reports",
    "output",
    "source_notes",
]

SUPPORTED_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".md", ".html", ".htm"
}

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


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def is_valid_tckn(value):
    if not re.fullmatch(r"[1-9]\d{10}", value):
        return False

    digits = [int(x) for x in value]

    rule_10 = ((sum(digits[0:9:2]) * 7) - sum(digits[1:8:2])) % 10
    rule_11 = sum(digits[:10]) % 10

    return digits[9] == rule_10 and digits[10] == rule_11


def normalize_phone(value):
    digits = re.sub(r"\D", "", value)

    if digits.startswith("90") and len(digits) == 12:
        digits = "0" + digits[2:]

    if digits.startswith("5") and len(digits) == 10:
        digits = "0" + digits

    return digits


def mask_text(text):
    def tc_replacer(match):
        value = match.group(1)
        if is_valid_tckn(value):
            return value[:2] + "*******" + value[-2:]
        return value

    def phone_replacer(match):
        value = match.group(0)
        digits = normalize_phone(value)

        if len(digits) == 11 and digits.startswith("05"):
            return digits[:2] + "********" + digits[-2:]

        return "[GSM_MASKELENDI]"

    def email_replacer(match):
        value = match.group(0)
        local, domain = value.split("@", 1)
        if len(local) <= 2:
            return local[0] + "***@" + domain
        return local[0] + "***" + local[-1] + "@" + domain

    def iban_replacer(match):
        compact = re.sub(r"\s|-", "", match.group(0)).upper()
        return compact[:4] + "***************" + compact[-4:]

    text = TC_REGEX.sub(tc_replacer, text)
    text = PHONE_REGEX.sub(phone_replacer, text)
    text = EMAIL_REGEX.sub(email_replacer, text)
    text = IBAN_REGEX.sub(iban_replacer, text)

    return text


def iter_files(folders):
    for folder in folders:
        root = BASE_DIR / folder

        if not root.exists():
            continue

        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield path


def safe_read_lines(path):
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as f:
            for idx, line in enumerate(f, start=1):
                yield idx, line.rstrip("\n")
    except Exception as e:
        yield 0, f"[OKUNAMADI] {e}"


def json_flatten_strings(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from json_flatten_strings(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from json_flatten_strings(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix, obj
    else:
        return


def iter_searchable_records(path):
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
            for key, text in json_flatten_strings(data):
                if str(text).strip():
                    yield key, str(text)
            return
        except Exception:
            pass

    for line_no, line in safe_read_lines(path):
        if line.strip():
            yield str(line_no), line


def make_matcher(query, regex=False, case_sensitive=False):
    if regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(query, flags=flags)

        def matcher(text):
            return bool(pattern.search(text))

        return matcher

    needle = query if case_sensitive else query.casefold()

    def matcher(text):
        hay = text if case_sensitive else text.casefold()
        return needle in hay

    return matcher


def shorten(text, limit=350):
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def main():
    parser = argparse.ArgumentParser(description="PII Leak Radar genel içerik arama")
    parser.add_argument("--q", required=True, help="Aranacak kelime veya regex")
    parser.add_argument("--regex", action="store_true", help="Regex modu")
    parser.add_argument("--case-sensitive", action="store_true", help="Büyük/küçük harf duyarlı")
    parser.add_argument(
        "--folders",
        default=",".join(DEFAULT_FOLDERS),
        help="Virgülle klasör listesi. Örn: input,reports,source_notes"
    )
    parser.add_argument("--max", type=int, default=200, help="Maksimum bulgu sayısı")
    parser.add_argument("--out-prefix", default="", help="Çıktı dosya öneki")
    args = parser.parse_args()

    folders = [x.strip() for x in args.folders.split(",") if x.strip()]
    matcher = make_matcher(args.q, regex=args.regex, case_sensitive=args.case_sensitive)

    results = []
    scanned_files = 0

    for path in iter_files(folders):
        scanned_files += 1
        rel = str(path.relative_to(BASE_DIR))

        for loc, text in iter_searchable_records(path):
            if matcher(text):
                masked = mask_text(text)
                results.append({
                    "file": rel,
                    "location": loc,
                    "snippet_masked": shorten(masked),
                })

                if len(results) >= args.max:
                    break

        if len(results) >= args.max:
            break

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = args.out_prefix.strip() or "content_search"
    out_csv = BASE_DIR / "output" / f"{prefix}_{timestamp}.csv"
    out_md = BASE_DIR / "reports" / f"{prefix}_{timestamp}.md"

    (BASE_DIR / "output").mkdir(exist_ok=True)
    (BASE_DIR / "reports").mkdir(exist_ok=True)

    with out_csv.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "location", "snippet_masked"]
        )
        writer.writeheader()
        writer.writerows(results)

    lines = []
    lines.append("# PII Leak Radar Genel İçerik Arama Raporu")
    lines.append("")
    lines.append(f"- Üretim zamanı: `{now_iso()}`")
    lines.append(f"- Arama ifadesi: `{args.q}`")
    lines.append(f"- Regex modu: `{args.regex}`")
    lines.append(f"- Taranan klasörler: `{', '.join(folders)}`")
    lines.append(f"- Taranan dosya sayısı: `{scanned_files}`")
    lines.append(f"- Eşleşme sayısı: `{len(results)}`")
    lines.append("")
    lines.append("## Bulgular")
    lines.append("")

    if not results:
        lines.append("Eşleşme bulunamadı.")
    else:
        for i, item in enumerate(results, start=1):
            lines.append(f"### Eşleşme {i}")
            lines.append("")
            lines.append(f"- Dosya: `{item['file']}`")
            lines.append(f"- Konum/Satır: `{item['location']}`")
            lines.append(f"- Maskelenmiş özet: `{item['snippet_masked']}`")
            lines.append("")

    out_md.write_text("\n".join(lines), encoding="utf-8")

    print("Genel içerik arama tamamlandı.")
    print(f"Taranan dosya sayısı: {scanned_files}")
    print(f"Eşleşme sayısı: {len(results)}")
    print(f"CSV: {out_csv}")
    print(f"Rapor: {out_md}")

    if results:
        print("")
        print("İlk eşleşmeler:")
        for item in results[:10]:
            print(f"- {item['file']}:{item['location']} | {item['snippet_masked']}")


if __name__ == "__main__":
    main()

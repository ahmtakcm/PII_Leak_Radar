# -*- coding: utf-8 -*-
"""
PII Leak Radar - Kaynak İçinde Manuel Arama

Amaç:
- configs/sources.json içindeki kaynak kayıtlarında arama yapmak.
- source_notes altındaki kaynak notlarında arama yapmak.
- Kaynak ref/path alanı yerel proje içi dosya veya klasör gösteriyorsa orada arama yapmak.
- Eşleşmeleri PII maskeli şekilde CSV ve Markdown raporlamak.

Bu araç:
- İnternete bağlanmaz.
- Telegram/Discord kanal/bot/panel aramaz.
- Kişisel veri sorgusu yapmaz.
- Sadece kullanıcının projeye eklediği kaynak kayıtları ve yerel dosyalar içinde arama yapar.
"""

import argparse
import csv
import json
import re
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = BASE_DIR / "configs"
SOURCE_NOTES_DIR = BASE_DIR / "source_notes"
OUTPUT_DIR = BASE_DIR / "output"
REPORTS_DIR = BASE_DIR / "reports"
SOURCES_FILE = CONFIG_DIR / "sources.json"

OUTPUT_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

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


def load_sources():
    if not SOURCES_FILE.exists():
        return []

    try:
        data = json.loads(SOURCES_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


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
        try:
            local, domain = value.split("@", 1)
            if len(local) <= 2:
                return local[0] + "***@" + domain
            return local[0] + "***" + local[-1] + "@" + domain
        except Exception:
            return "[EMAIL_MASKELENDI]"

    def iban_replacer(match):
        compact = re.sub(r"\s|-", "", match.group(0)).upper()
        if len(compact) >= 8:
            return compact[:4] + "***************" + compact[-4:]
        return "[IBAN_MASKELENDI]"

    text = TC_REGEX.sub(tc_replacer, text)
    text = PHONE_REGEX.sub(phone_replacer, text)
    text = EMAIL_REGEX.sub(email_replacer, text)
    text = IBAN_REGEX.sub(iban_replacer, text)

    return text


def shorten(text, limit=420):
    text = re.sub(r"\s+", " ", str(text)).strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def make_matcher(query, regex=False, case_sensitive=False):
    if regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(query, flags=flags)

        def matcher(text):
            return bool(pattern.search(str(text)))

        return matcher

    needle = query if case_sensitive else query.casefold()

    def matcher(text):
        hay = str(text) if case_sensitive else str(text).casefold()
        return needle in hay

    return matcher


def json_flatten_strings(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            next_prefix = f"{prefix}.{k}" if prefix else str(k)
            yield from json_flatten_strings(v, next_prefix)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from json_flatten_strings(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix, obj
    elif obj is not None:
        yield prefix, str(obj)


def iter_file_records(path):
    if not path.exists() or not path.is_file():
        return

    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
            for key, text in json_flatten_strings(data):
                if str(text).strip():
                    yield str(key), str(text)
            return
        except Exception:
            pass

    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as f:
            for idx, line in enumerate(f, start=1):
                line = line.rstrip("\n")
                if line.strip():
                    yield str(idx), line
    except Exception as e:
        yield "0", f"[OKUNAMADI] {e}"


def is_inside_base(path):
    try:
        resolved = path.resolve()
        base = BASE_DIR.resolve()
        return resolved == base or base in resolved.parents
    except Exception:
        return False


def looks_like_url(value):
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", value.strip()))


def resolve_local_ref(ref_value):
    if not ref_value:
        return None

    ref_value = str(ref_value).strip()

    if not ref_value:
        return None

    if looks_like_url(ref_value):
        return None

    candidate = Path(ref_value)

    if not candidate.is_absolute():
        candidate = BASE_DIR / candidate

    try:
        candidate = candidate.resolve()
    except Exception:
        return None

    # Güvenlik: varsayılan olarak proje klasörü dışındaki path'lerde arama yapma.
    if not is_inside_base(candidate):
        return None

    if candidate.exists():
        return candidate

    return None


def iter_supported_files(root):
    if root.is_file():
        if root.suffix.lower() in SUPPORTED_EXTENSIONS:
            yield root
        return

    if root.is_dir():
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield path


def get_source_note_files(source_id):
    if not SOURCE_NOTES_DIR.exists():
        return []

    return sorted(SOURCE_NOTES_DIR.glob(f"{source_id}_*.md"))


def source_passes_filters(source, args):
    if args.source_id and source.get("id") != args.source_id:
        return False

    if args.status and source.get("status") != args.status:
        return False

    if args.type and source.get("type") != args.type:
        return False

    if args.tag:
        tags = [str(x).casefold() for x in source.get("tags", [])]
        if args.tag.casefold() not in tags:
            return False

    return True


def source_metadata_records(source):
    fields = [
        "id",
        "name",
        "type",
        "access_type",
        "status",
        "tags",
        "legal_basis",
        "path_or_ref",
        "notes",
        "created_at",
        "updated_at",
    ]

    for field in fields:
        value = source.get(field, "")
        if isinstance(value, list):
            value = ", ".join(str(x) for x in value)
        if str(value).strip():
            yield field, str(value)


def add_result(results, source, area, file_path, location, text):
    masked = mask_text(str(text))

    if file_path:
        try:
            file_value = str(file_path.relative_to(BASE_DIR))
        except Exception:
            file_value = str(file_path)
    else:
        file_value = ""

    results.append({
        "source_id": source.get("id", ""),
        "source_name": source.get("name", ""),
        "source_status": source.get("status", ""),
        "source_type": source.get("type", ""),
        "area": area,
        "file": file_value,
        "location": str(location),
        "snippet_masked": shorten(masked),
    })


def search_sources(args):
    sources = load_sources()
    matcher = make_matcher(
        args.q,
        regex=args.regex,
        case_sensitive=args.case_sensitive
    )

    results = []
    scanned_sources = 0
    scanned_files = 0

    for source in sources:
        if not source_passes_filters(source, args):
            continue

        scanned_sources += 1

        # 1) Kaynak metadata araması
        if not args.no_metadata:
            for field, text in source_metadata_records(source):
                if matcher(text):
                    add_result(
                        results,
                        source,
                        "source_metadata",
                        None,
                        field,
                        text
                    )
                    if len(results) >= args.max:
                        break

        if len(results) >= args.max:
            break

        # 2) Kaynak not dosyalarında arama
        if not args.no_notes:
            for note_path in get_source_note_files(source.get("id", "")):
                scanned_files += 1
                for loc, text in iter_file_records(note_path):
                    if matcher(text):
                        add_result(
                            results,
                            source,
                            "source_note",
                            note_path,
                            loc,
                            text
                        )
                        if len(results) >= args.max:
                            break
                if len(results) >= args.max:
                    break

        if len(results) >= args.max:
            break

        # 3) Kaynak ref/path yerel dosya veya klasör ise içinde arama
        if not args.no_ref:
            local_ref = resolve_local_ref(source.get("path_or_ref", ""))
            if local_ref:
                for file_path in iter_supported_files(local_ref):
                    scanned_files += 1
                    for loc, text in iter_file_records(file_path):
                        if matcher(text):
                            add_result(
                                results,
                                source,
                                "referenced_local_content",
                                file_path,
                                loc,
                                text
                            )
                            if len(results) >= args.max:
                                break
                    if len(results) >= args.max:
                        break

        if len(results) >= args.max:
            break

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_prefix = "source_search"
    out_csv = OUTPUT_DIR / f"{safe_prefix}_{timestamp}.csv"
    out_md = REPORTS_DIR / f"{safe_prefix}_{timestamp}.md"

    with out_csv.open("w", encoding="utf-8-sig", newline="") as f:
        fieldnames = [
            "source_id",
            "source_name",
            "source_status",
            "source_type",
            "area",
            "file",
            "location",
            "snippet_masked",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    lines = []
    lines.append("# PII Leak Radar Kaynak İçi Manuel Arama Raporu")
    lines.append("")
    lines.append(f"- Üretim zamanı: `{now_iso()}`")
    lines.append(f"- Arama ifadesi: `{args.q}`")
    lines.append(f"- Regex modu: `{args.regex}`")
    lines.append(f"- Kaynak filtresi: `{args.source_id or '-'}`")
    lines.append(f"- Tip filtresi: `{args.type or '-'}`")
    lines.append(f"- Durum filtresi: `{args.status or '-'}`")
    lines.append(f"- Tag filtresi: `{args.tag or '-'}`")
    lines.append(f"- Taranan kaynak sayısı: `{scanned_sources}`")
    lines.append(f"- Taranan dosya sayısı: `{scanned_files}`")
    lines.append(f"- Eşleşme sayısı: `{len(results)}`")
    lines.append("")
    lines.append("## Bulgular")
    lines.append("")

    if not results:
        lines.append("Eşleşme bulunamadı.")
    else:
        for idx, item in enumerate(results, start=1):
            lines.append(f"### Eşleşme {idx}")
            lines.append("")
            lines.append(f"- Kaynak: `{item['source_id']} - {item['source_name']}`")
            lines.append(f"- Kaynak tipi: `{item['source_type']}`")
            lines.append(f"- Kaynak durumu: `{item['source_status']}`")
            lines.append(f"- Alan: `{item['area']}`")
            lines.append(f"- Dosya: `{item['file']}`")
            lines.append(f"- Konum/Satır: `{item['location']}`")
            lines.append(f"- Maskelenmiş özet: `{item['snippet_masked']}`")
            lines.append("")

    lines.append("## Not")
    lines.append("")
    lines.append(
        "Bu araç yalnızca kayıtlı kaynakların metadata, not dosyası ve proje içindeki yerel ref/path içeriklerinde arama yapar. "
        "Dış kaynaklarda kanal, bot, panel veya kişisel veri sorgusu yapmaz."
    )

    out_md.write_text("\n".join(lines), encoding="utf-8")

    print("Kaynak içi manuel arama tamamlandı.")
    print(f"Taranan kaynak sayısı: {scanned_sources}")
    print(f"Taranan dosya sayısı: {scanned_files}")
    print(f"Eşleşme sayısı: {len(results)}")
    print(f"CSV: {out_csv}")
    print(f"Rapor: {out_md}")

    if results:
        print("")
        print("İlk eşleşmeler:")
        for item in results[:10]:
            print(
                f"- {item['source_id']} | {item['area']} | "
                f"{item['file']}:{item['location']} | {item['snippet_masked']}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="PII Leak Radar kaynak içi manuel arama"
    )

    parser.add_argument("--q", required=True, help="Aranacak kelime veya regex")
    parser.add_argument("--regex", action="store_true", help="Regex modu")
    parser.add_argument("--case-sensitive", action="store_true", help="Büyük/küçük harf duyarlı")

    parser.add_argument("--source-id", default="", help="Sadece belirli kaynak ID içinde ara. Örn: SRC-0002")
    parser.add_argument("--status", default="", help="Duruma göre filtrele. Örn: active, watch, disabled")
    parser.add_argument("--type", default="", help="Kaynak tipine göre filtrele. Örn: telegram_export")
    parser.add_argument("--tag", default="", help="Etikete göre filtrele. Örn: telegram")

    parser.add_argument("--no-metadata", action="store_true", help="Kaynak metadata içinde arama yapma")
    parser.add_argument("--no-notes", action="store_true", help="Kaynak notlarında arama yapma")
    parser.add_argument("--no-ref", action="store_true", help="Kaynak ref/path içeriğinde arama yapma")

    parser.add_argument("--max", type=int, default=300, help="Maksimum eşleşme sayısı")

    args = parser.parse_args()
    search_sources(args)


if __name__ == "__main__":
    main()

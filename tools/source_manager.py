# -*- coding: utf-8 -*-
"""
PII Leak Radar - Kaynak Yönetimi

Amaç:
- İnceleme kaynaklarını kayıt altında tutmak.
- Kaynakları listelemek, aramak, aktif/pasif yapmak.
- Her kaynak için not dosyası oluşturmak.

Bu araç:
- İnternette kanal/bot/panel aramaz.
- Telegram/Discord sorgu botu kullanmaz.
- Kişisel veri sorgusu yapmaz.
- Yalnızca kullanıcının eklediği kaynak kayıtlarını yönetir.
"""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = BASE_DIR / "configs"
SOURCE_NOTES_DIR = BASE_DIR / "source_notes"
SOURCES_FILE = CONFIG_DIR / "sources.json"

CONFIG_DIR.mkdir(exist_ok=True)
SOURCE_NOTES_DIR.mkdir(exist_ok=True)

ALLOWED_SOURCE_TYPES = [
    "web_public",
    "paste_public",
    "code_repo_public",
    "threat_feed_public",
    "malware_domain_feed",
    "telegram_export",
    "discord_export",
    "irc_log",
    "user_report",
    "forensic_note",
    "other",
]

ALLOWED_ACCESS_TYPES = [
    "public",
    "export",
    "user_report",
    "own_asset",
    "official_request",
    "manual_note",
]

ALLOWED_STATUS = [
    "active",
    "watch",
    "disabled",
    "archived",
]


SEED_SOURCES = [
    {
        "id": "SRC-0001",
        "name": "Yerel input klasörü",
        "type": "forensic_note",
        "access_type": "own_asset",
        "status": "active",
        "tags": ["local", "input", "analysis"],
        "legal_basis": "Kullanıcı tarafından sağlanan yerel dosyalar.",
        "path_or_ref": "input/",
        "notes": "PII Leak Radar input klasörü.",
        "created_at": "",
        "updated_at": "",
    },
    {
        "id": "SRC-0002",
        "name": "İhbar / ekran görüntüsü notları",
        "type": "user_report",
        "access_type": "user_report",
        "status": "active",
        "tags": ["ihbar", "evidence", "manual"],
        "legal_basis": "Kullanıcıya gelen ihbar veya delil notu.",
        "path_or_ref": "evidence/",
        "notes": "Ekran görüntüsü, OCR metni veya manuel delil notları.",
        "created_at": "",
        "updated_at": "",
    },
    {
        "id": "SRC-0003",
        "name": "Açık tehdit kaynağı notları",
        "type": "threat_feed_public",
        "access_type": "public",
        "status": "watch",
        "tags": ["threat-intel", "public", "watch"],
        "legal_basis": "Açık ve yasal tehdit istihbaratı kaynaklarından manuel not.",
        "path_or_ref": "source_notes/",
        "notes": "Otomatik toplama yapmaz; manuel kaynak notları için yer tutucu.",
        "created_at": "",
        "updated_at": "",
    },
]


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_sources():
    if not SOURCES_FILE.exists():
        return []

    try:
        return json.loads(SOURCES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_sources(sources):
    SOURCES_FILE.write_text(
        json.dumps(sources, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def slugify(value):
    value = value.strip().lower()
    value = value.replace("ı", "i").replace("ğ", "g").replace("ü", "u")
    value = value.replace("ş", "s").replace("ö", "o").replace("ç", "c")
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "source"


def next_source_id(sources):
    max_no = 0
    for item in sources:
        sid = str(item.get("id", ""))
        m = re.match(r"SRC-(\d+)", sid)
        if m:
            max_no = max(max_no, int(m.group(1)))
    return f"SRC-{max_no + 1:04d}"


def create_note_file(source):
    sid = source["id"]
    slug = slugify(source["name"])
    note_path = SOURCE_NOTES_DIR / f"{sid}_{slug}.md"

    if note_path.exists():
        return note_path

    lines = [
        f"# Kaynak Notu - {source['id']}",
        "",
        f"- Kaynak adı: {source['name']}",
        f"- Tür: {source['type']}",
        f"- Erişim tipi: {source['access_type']}",
        f"- Durum: {source['status']}",
        f"- Oluşturma: {source['created_at']}",
        f"- Referans/Yol: {source.get('path_or_ref', '')}",
        "",
        "## Hukuki / operasyonel not",
        "",
        source.get("legal_basis", ""),
        "",
        "## İnceleme notları",
        "",
        "- ",
        "",
    ]

    note_path.write_text("\n".join(lines), encoding="utf-8")
    return note_path


def init_sources(args):
    existing = load_sources()

    if existing and not args.force:
        print(f"Kaynak dosyası zaten var: {SOURCES_FILE}")
        print("Sıfırlamak için: python .\\tools\\source_manager.py init --force")
        return

    timestamp = now_iso()
    seeded = []

    for item in SEED_SOURCES:
        new_item = dict(item)
        new_item["created_at"] = timestamp
        new_item["updated_at"] = timestamp
        seeded.append(new_item)
        create_note_file(new_item)

    save_sources(seeded)

    print("Kaynak yönetimi hazır.")
    print(f"Kaynak dosyası: {SOURCES_FILE}")
    print(f"Kaynak notları: {SOURCE_NOTES_DIR}")


def list_sources(args):
    sources = load_sources()

    if args.status:
        sources = [x for x in sources if x.get("status") == args.status]

    if args.type:
        sources = [x for x in sources if x.get("type") == args.type]

    if not sources:
        print("Kayıtlı kaynak bulunamadı.")
        return

    for item in sources:
        tags = ", ".join(item.get("tags", []))
        print(
            f"{item.get('id')} | {item.get('status')} | {item.get('type')} | "
            f"{item.get('access_type')} | {item.get('name')} | tags=[{tags}]"
        )


def add_source(args):
    if args.type not in ALLOWED_SOURCE_TYPES:
        raise SystemExit(
            "Geçersiz kaynak türü. Geçerli türler: "
            + ", ".join(ALLOWED_SOURCE_TYPES)
        )

    if args.access not in ALLOWED_ACCESS_TYPES:
        raise SystemExit(
            "Geçersiz erişim tipi. Geçerli tipler: "
            + ", ".join(ALLOWED_ACCESS_TYPES)
        )

    if args.status not in ALLOWED_STATUS:
        raise SystemExit(
            "Geçersiz durum. Geçerli durumlar: "
            + ", ".join(ALLOWED_STATUS)
        )

    # Güvenlik uyarısı: panel/sorgu gibi kaynaklar aktif keşif için kullanılmamalı.
    risky_words = ["panel", "sorgu", "tc", "gsm", "mernis", "adres"]
    name_lc = args.name.casefold()
    ref_lc = (args.ref or "").casefold()

    if any(w in name_lc or w in ref_lc for w in risky_words):
        if args.access not in ["user_report", "official_request", "manual_note", "export"]:
            print("UYARI: Bu kaynak adı/ref hassas görünüyor.")
            print("Bu sistem aktif sorgu veya kanal/bot keşfi yapmaz.")
            print("Kaynak sadece ihbar/export/resmi inceleme notu olarak tutulmalıdır.")

    sources = load_sources()
    timestamp = now_iso()

    source = {
        "id": next_source_id(sources),
        "name": args.name,
        "type": args.type,
        "access_type": args.access,
        "status": args.status,
        "tags": [x.strip() for x in args.tags.split(",") if x.strip()],
        "legal_basis": args.legal_basis or "",
        "path_or_ref": args.ref or "",
        "notes": args.notes or "",
        "created_at": timestamp,
        "updated_at": timestamp,
    }

    sources.append(source)
    save_sources(sources)
    note_path = create_note_file(source)

    print("Kaynak eklendi.")
    print(f"ID: {source['id']}")
    print(f"Not dosyası: {note_path}")


def set_status(args):
    sources = load_sources()
    found = False

    for item in sources:
        if item.get("id") == args.id:
            item["status"] = args.status
            item["updated_at"] = now_iso()
            found = True
            break

    if not found:
        raise SystemExit(f"Kaynak bulunamadı: {args.id}")

    save_sources(sources)
    print(f"{args.id} durumu güncellendi: {args.status}")


def search_sources(args):
    sources = load_sources()
    q = args.q.casefold()

    results = []
    for item in sources:
        blob = json.dumps(item, ensure_ascii=False).casefold()
        if q in blob:
            results.append(item)

    if not results:
        print("Kaynak kaydında eşleşme yok.")
        return

    for item in results:
        tags = ", ".join(item.get("tags", []))
        print(
            f"{item.get('id')} | {item.get('status')} | {item.get('type')} | "
            f"{item.get('name')} | tags=[{tags}]"
        )


def show_source(args):
    sources = load_sources()
    for item in sources:
        if item.get("id") == args.id:
            print(json.dumps(item, ensure_ascii=False, indent=2))
            return

    raise SystemExit(f"Kaynak bulunamadı: {args.id}")


def main():
    parser = argparse.ArgumentParser(
        description="PII Leak Radar kaynak yönetimi"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Kaynak dosyasını başlat")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=init_sources)

    p_list = sub.add_parser("list", help="Kaynakları listele")
    p_list.add_argument("--status", choices=ALLOWED_STATUS)
    p_list.add_argument("--type", choices=ALLOWED_SOURCE_TYPES)
    p_list.set_defaults(func=list_sources)

    p_add = sub.add_parser("add", help="Yeni kaynak ekle")
    p_add.add_argument("--name", required=True)
    p_add.add_argument("--type", required=True, choices=ALLOWED_SOURCE_TYPES)
    p_add.add_argument("--access", required=True, choices=ALLOWED_ACCESS_TYPES)
    p_add.add_argument("--status", default="active", choices=ALLOWED_STATUS)
    p_add.add_argument("--tags", default="")
    p_add.add_argument("--ref", default="")
    p_add.add_argument("--legal-basis", default="")
    p_add.add_argument("--notes", default="")
    p_add.set_defaults(func=add_source)

    p_status = sub.add_parser("status", help="Kaynak durumunu değiştir")
    p_status.add_argument("--id", required=True)
    p_status.add_argument("--status", required=True, choices=ALLOWED_STATUS)
    p_status.set_defaults(func=set_status)

    p_search = sub.add_parser("search", help="Kaynak kayıtlarında ara")
    p_search.add_argument("--q", required=True)
    p_search.set_defaults(func=search_sources)

    p_show = sub.add_parser("show", help="Kaynak detayını göster")
    p_show.add_argument("--id", required=True)
    p_show.set_defaults(func=show_source)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

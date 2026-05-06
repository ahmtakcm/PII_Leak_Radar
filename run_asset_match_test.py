from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.match_engine import scan_text

DEFAULT_SAMPLE_TEXT = """
Telegram leak dump içinde sample.person@example.com ve +905551112233 geçti.
Ayrıca login.example.net panel log ifadesi var.
Discord market paylaşımında example.com database adı da yazılmış.
Bu test dış bağlantı yapmaz, sadece local dry-run çalışır.
"""

def read_text_file(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError("Text file not found: " + str(p))
    return p.read_text(encoding="utf-8-sig", errors="replace")

def main() -> int:
    parser = argparse.ArgumentParser(description="PII Leak Radar Sprint 2 asset match dry-run test")
    parser.add_argument("--text", help="Taranacak düz metin")
    parser.add_argument("--file", help="Taranacak metni içeren dosya yolu")
    parser.add_argument("--asset-file", help="Asset JSON dosyası yolu. Varsayılan: local doluysa local, değilse sample")
    parser.add_argument("--source-id", default="asset_match_test", help="Kaynak kimliği")
    parser.add_argument("--source-type", default="dry_run", help="Kaynak tipi")
    parser.add_argument("--json", action="store_true", help="Tam JSON çıktı ver")
    args = parser.parse_args()

    if args.file:
        text = read_text_file(args.file)
    elif args.text:
        text = args.text
    else:
        text = DEFAULT_SAMPLE_TEXT

    result = scan_text(
        text,
        source_id=args.source_id,
        source_type=args.source_type,
        asset_file=args.asset_file,
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    summary = result.get("summary", {})
    matches = result.get("matches", [])

    print("ASSET_MATCH_TEST_OK")
    print("source_id=" + str(result.get("source_id")))
    print("source_type=" + str(result.get("source_type")))
    print("match_count=" + str(summary.get("match_count", 0)))
    print("asset_count=" + str(summary.get("asset_count", 0)))
    print("max_risk_score=" + str(summary.get("max_risk_score", 0)))
    print("")

    if not matches:
        print("No matches found.")
        return 0

    print("Top matches:")
    for item in matches[:10]:
        print("- asset_id={asset_id} type={value_type} match={match_type} risk={risk_score} value={value}".format(
            asset_id=item.get("asset_id"),
            value_type=item.get("value_type"),
            match_type=item.get("match_type"),
            risk_score=item.get("risk_score"),
            value=item.get("matched_value_masked"),
        ))
        snippet = item.get("snippet_masked") or ""
        if snippet:
            print("  snippet=" + snippet)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

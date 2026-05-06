import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.registry_loader import load_registry
from core.source_catalog import build_catalog, load_scope
from core.source_catalog_report import write_catalog_html, write_catalog_json


def main():
    registry = load_registry(ROOT / "registry.yml")
    scope_cfg = load_scope(ROOT / "config" / "scope.yml")

    rows = build_catalog(registry, scope_cfg)

    html_path = write_catalog_html(rows, ROOT / "reports" / "source_catalog.html")
    json_path = write_catalog_json(rows, ROOT / "reports" / "source_catalog.json")

    print("=== PII Leak Radar | Source Catalog Review ===")
    print(f"Kaynak sayısı: {len(rows)}")

    for r in rows:
        print(
            f"[{r.get('status')}] {r.get('id')} | "
            f"enabled={r.get('enabled')} | "
            f"legal={r.get('legal_level')} | "
            f"blocker={r.get('blocker') or '-'}"
        )

    print("")
    print(f"HTML katalog: {html_path}")
    print(f"JSON katalog: {json_path}")
    print("")
    print("Not: Bu adım kaynak envanteri çıkarır; pasif kaynakları taramaz veya erişim yapmaz.")


if __name__ == "__main__":
    main()

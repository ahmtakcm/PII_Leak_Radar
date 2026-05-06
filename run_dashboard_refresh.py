import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.dashboard import write_dashboard
from core.dedup_store import DedupStore


def main():
    store = DedupStore(ROOT / "data" / "pii_radar.db")

    recent = store.recent_observations(limit=300)
    source_runs = store.latest_source_runs()

    dashboard_path = write_dashboard(
        recent,
        ROOT / "reports" / "dashboard.html",
        source_runs=source_runs,
    )

    store.close()

    print("=== PII Leak Radar | Dashboard Refresh ===")
    print(f"Gözlem: {len(recent)}")
    print(f"Kaynak durumu: {len(source_runs)}")
    print(f"HTML dashboard: {dashboard_path}")


if __name__ == "__main__":
    main()

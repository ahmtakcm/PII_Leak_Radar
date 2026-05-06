import argparse
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.dashboard import write_dashboard
from core.dedup_store import DedupStore


DB_PATH = ROOT / "data" / "pii_radar.db"


def connect():
    if not DB_PATH.exists():
        raise SystemExit(f"DB bulunamadi: {DB_PATH}")
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def purge_github_test(conn):
    cur1 = conn.execute(
        "DELETE FROM observations WHERE source_id = ?",
        ("github_public_code_search",),
    )
    cur2 = conn.execute(
        "DELETE FROM source_runs WHERE source_id = ?",
        ("github_public_code_search",),
    )
    return cur1.rowcount, cur2.rowcount


def purge_test_export(conn):
    cur = conn.execute(
        """
        DELETE FROM observations
        WHERE source_id = ?
          AND payload_json LIKE ?
        """,
        ("telegram_discord_exports", "%test_export.txt%"),
    )
    return cur.rowcount


def purge_old_observations(conn, keep_days):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(keep_days))).isoformat()
    cur = conn.execute(
        "DELETE FROM observations WHERE last_seen < ?",
        (cutoff,),
    )
    return cur.rowcount


def purge_old_source_runs(conn, keep_days):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(keep_days))).isoformat()
    cur = conn.execute(
        "DELETE FROM source_runs WHERE checked_at < ?",
        (cutoff,),
    )
    return cur.rowcount


def vacuum(conn):
    conn.execute("VACUUM")


def refresh_dashboard():
    store = DedupStore(ROOT / "data" / "pii_radar.db")
    recent = store.recent_observations(limit=300)
    source_runs = store.latest_source_runs()
    dashboard_path = write_dashboard(
        recent,
        ROOT / "reports" / "dashboard.html",
        source_runs=source_runs,
    )
    store.close()
    return dashboard_path, len(recent), len(source_runs)


def main():
    parser = argparse.ArgumentParser(description="PII Leak Radar maintenance helper")
    parser.add_argument("--purge-github-test", action="store_true")
    parser.add_argument("--purge-test-export", action="store_true")
    parser.add_argument("--keep-observations-days", type=int, default=None)
    parser.add_argument("--keep-source-runs-days", type=int, default=None)
    parser.add_argument("--vacuum", action="store_true")
    args = parser.parse_args()

    conn = connect()

    print("=== PII Leak Radar | Maintenance ===")

    if args.purge_github_test:
        obs, runs = purge_github_test(conn)
        print(f"[OK] GitHub test kayitlari temizlendi | observations={obs} source_runs={runs}")

    if args.purge_test_export:
        obs = purge_test_export(conn)
        print(f"[OK] test_export.txt bulgulari temizlendi | observations={obs}")

    if args.keep_observations_days is not None:
        obs = purge_old_observations(conn, args.keep_observations_days)
        print(f"[OK] Eski observation kayitlari temizlendi | keep_days={args.keep_observations_days} observations={obs}")

    if args.keep_source_runs_days is not None:
        runs = purge_old_source_runs(conn, args.keep_source_runs_days)
        print(f"[OK] Eski source_run kayitlari temizlendi | keep_days={args.keep_source_runs_days} source_runs={runs}")

    conn.commit()

    if args.vacuum:
        vacuum(conn)
        print("[OK] SQLite VACUUM tamamlandi")

    conn.close()

    dashboard_path, observation_count, source_run_count = refresh_dashboard()

    print("")
    print("=== OZET ===")
    print(f"Gozlem sayisi: {observation_count}")
    print(f"Kaynak durumu sayisi: {source_run_count}")
    print(f"Dashboard: {dashboard_path}")


if __name__ == "__main__":
    main()

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any


class DedupStore:
    def __init__(self, db_path: str = "data/pii_radar.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                external_id TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                title TEXT,
                risk_score INTEGER,
                risk_label TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                payload_json TEXT,
                UNIQUE(source_id, external_id)
            )
            """
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS source_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                source_name TEXT,
                status TEXT NOT NULL,
                fetched_count INTEGER NOT NULL DEFAULT 0,
                new_count INTEGER NOT NULL DEFAULT 0,
                duplicate_count INTEGER NOT NULL DEFAULT 0,
                error_message TEXT,
                suggested_action TEXT,
                checked_at TEXT NOT NULL,
                duration_ms INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        self.conn.commit()

    def close(self):
        self.conn.close()

    def add_observation(self, event: Dict[str, Any]) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        source_id = str(event.get("source_id", "unknown"))
        external_id = str(event.get("external_id") or self._hash_event(event))
        event_hash = self._hash_event(event)
        title = str(event.get("title", ""))[:500]
        payload_json = json.dumps(event, ensure_ascii=False, sort_keys=True)

        try:
            self.conn.execute(
                """
                INSERT INTO observations
                (source_id, external_id, event_hash, title, risk_score, risk_label,
                 first_seen, last_seen, seen_count, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    source_id,
                    external_id,
                    event_hash,
                    title,
                    int(event.get("risk_score", 0)),
                    str(event.get("risk_label", "")),
                    now,
                    now,
                    payload_json,
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            self.conn.execute(
                """
                UPDATE observations
                SET last_seen = ?, seen_count = seen_count + 1, event_hash = ?,
                    risk_score = ?, risk_label = ?, payload_json = ?
                WHERE source_id = ? AND external_id = ?
                """,
                (
                    now,
                    event_hash,
                    int(event.get("risk_score", 0)),
                    str(event.get("risk_label", "")),
                    payload_json,
                    source_id,
                    external_id,
                ),
            )
            self.conn.commit()
            return False

    def record_source_run(
        self,
        source_id: str,
        source_name: str,
        status: str,
        fetched_count: int = 0,
        new_count: int = 0,
        duplicate_count: int = 0,
        error_message: str = "",
        suggested_action: str = "",
        duration_ms: int = 0,
    ):
        now = datetime.now(timezone.utc).isoformat()

        self.conn.execute(
            """
            INSERT INTO source_runs
            (source_id, source_name, status, fetched_count, new_count,
             duplicate_count, error_message, suggested_action, checked_at, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                source_name,
                status,
                int(fetched_count),
                int(new_count),
                int(duplicate_count),
                error_message[:1000] if error_message else "",
                suggested_action[:1000] if suggested_action else "",
                now,
                int(duration_ms),
            ),
        )
        self.conn.commit()

    def recent_observations(self, limit: int = 200):
        cur = self.conn.execute(
            """
            SELECT * FROM observations
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

        rows = []
        for row in cur.fetchall():
            item = dict(row)
            payload = {}

            try:
                payload_raw = item.get("payload_json") or "{}"
                payload = json.loads(payload_raw)
            except Exception:
                payload = {}

            for key in (
                "type",
                "recommended_action",
                "legal_level",
                "source_category",
                "cve",
                "cvss",
                "severity",
                "url_status",
                "threat",
            ):
                if key in payload:
                    item[key] = payload.get(key)

            rows.append(item)

        return rows

    def latest_source_runs(self):
        cur = self.conn.execute(
            """
            SELECT sr.*
            FROM source_runs sr
            INNER JOIN (
                SELECT source_id, MAX(id) AS max_id
                FROM source_runs
                GROUP BY source_id
            ) latest
            ON sr.source_id = latest.source_id AND sr.id = latest.max_id
            ORDER BY sr.source_id ASC
            """
        )
        return [dict(row) for row in cur.fetchall()]

    @staticmethod
    def _hash_event(event: Dict[str, Any]) -> str:
        raw = json.dumps(event, ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

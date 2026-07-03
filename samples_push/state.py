from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


PROD_TARGET = "https://www.filescan.io"

SCHEMA = """
CREATE TABLE IF NOT EXISTS processed (
  sha256 TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  flow_id TEXT,
  uploaded_at TEXT NOT NULL,
  status TEXT,
  PRIMARY KEY (sha256, target)
);
CREATE TABLE IF NOT EXISTS source_cursor (
  source TEXT PRIMARY KEY,
  cursor TEXT,
  updated_at TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class State:
    def __init__(self, db_path: Path) -> None:
        self.path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._migrate()
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def _migrate(self) -> None:
        cur = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='processed'"
        )
        if cur.fetchone() is None:
            return
        cur = self._conn.execute("PRAGMA table_info(processed)")
        cols = {row[1] for row in cur.fetchall()}
        if "target" in cols:
            return
        # Old schema: PK was sha256 alone; back-fill target=prod for all rows.
        self._conn.executescript(
            f"""
            CREATE TABLE processed_new (
              sha256 TEXT NOT NULL,
              target TEXT NOT NULL DEFAULT '',
              source TEXT NOT NULL,
              flow_id TEXT,
              uploaded_at TEXT NOT NULL,
              status TEXT,
              PRIMARY KEY (sha256, target)
            );
            INSERT INTO processed_new
              (sha256, target, source, flow_id, uploaded_at, status)
              SELECT sha256, '{PROD_TARGET}', source, flow_id, uploaded_at, status
              FROM processed;
            DROP TABLE processed;
            ALTER TABLE processed_new RENAME TO processed;
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def seen(self, sha256: str, target: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM processed WHERE sha256 = ? AND target = ? "
                "AND status IN ('uploaded', 'report_ready', 'vaulted')",
                (sha256.lower(), target),
            )
            return cur.fetchone() is not None

    def mark(
        self,
        sha256: str,
        source: str,
        target: str,
        flow_id: str | None,
        status: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO processed
                   (sha256, target, source, flow_id, uploaded_at, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (sha256.lower(), target, source, flow_id, _now(), status),
            )
            self._conn.commit()

    def list_replay_candidates(self, target: str) -> list[tuple[str, str]]:
        """Distinct (sha256, source) successfully uploaded to some other
        target but never recorded against ``target``. Used to re-send
        production-vaulted samples to staging (or vice versa)."""
        with self._lock:
            cur = self._conn.execute(
                """SELECT sha256, source FROM processed AS p
                   WHERE status IN ('uploaded', 'report_ready')
                     AND target != ?
                     AND NOT EXISTS (
                       SELECT 1 FROM processed AS q
                       WHERE q.sha256 = p.sha256 AND q.target = ?
                     )
                   GROUP BY sha256""",
                (target, target),
            )
            return [(row[0], row[1]) for row in cur.fetchall()]

    def get_cursor(self, source: str) -> str | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT cursor FROM source_cursor WHERE source = ?", (source,)
            )
            row = cur.fetchone()
            return row[0] if row else None

    def set_cursor(self, source: str, cursor: str) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO source_cursor (source, cursor, updated_at)
                   VALUES (?, ?, ?)""",
                (source, cursor, _now()),
            )
            self._conn.commit()

    def count_processed(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM processed")
            return cur.fetchone()[0]

    def clear_all(self) -> int:
        """Clear all processed records. Returns count of deleted records."""
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM processed")
            count = cur.fetchone()[0]
            self._conn.execute("DELETE FROM processed")
            self._conn.commit()
            return count

    def clear_target(self, target: str) -> int:
        """Clear processed records for a specific target. Returns count of deleted records."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM processed WHERE target = ?", (target,)
            )
            count = cur.fetchone()[0]
            self._conn.execute("DELETE FROM processed WHERE target = ?", (target,))
            self._conn.commit()
            return count

    def clear_cursors(self) -> int:
        """Clear all source cursors. Returns count of deleted records."""
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM source_cursor")
            count = cur.fetchone()[0]
            self._conn.execute("DELETE FROM source_cursor")
            self._conn.commit()
            return count

    def stats_by_day(self, days: int = 14) -> list[tuple[str, int]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT DATE(uploaded_at) AS day, COUNT(*) "
                "FROM processed "
                "WHERE uploaded_at >= DATE('now', ? || ' days') "
                "GROUP BY day ORDER BY day DESC",
                (f"-{days}",),
            )
            return cur.fetchall()

    def stats_by_day_source(self, days: int = 14) -> list[tuple[str, str, int]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT DATE(uploaded_at) AS day, source, COUNT(*) "
                "FROM processed "
                "WHERE uploaded_at >= DATE('now', ? || ' days') "
                "GROUP BY day, source ORDER BY day DESC, source",
                (f"-{days}",),
            )
            return cur.fetchall()

    def stats_by_source(self) -> list[tuple[str, int]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT source, COUNT(*) FROM processed "
                "GROUP BY source ORDER BY 2 DESC"
            )
            return cur.fetchall()

    def stats_by_status(self) -> list[tuple[str, int]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT COALESCE(status, 'unknown'), COUNT(*) FROM processed "
                "GROUP BY 1 ORDER BY 2 DESC"
            )
            return cur.fetchall()

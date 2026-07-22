from __future__ import annotations

import logging
import platform
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .state import SCHEMA


log = logging.getLogger(__name__)

# Matches the credential portion of an HTTPS remote URL, e.g.
# https://x-access-token:ghp_xxx@github.com/... -> https://***@github.com/...
# so a PAT embedded in STATE_REPO_URL never ends up in logs.
_CREDENTIAL_RE = re.compile(r"://[^/@\s]+@")


def _redact(text: str) -> str:
    return _CREDENTIAL_RE.sub("://***@", text)


class StateSync:
    """Syncs state.db via a private git repo (e.g. GitHub) for multi-machine dedup.

    Pull and push MERGE the `processed` / `source_cursor` tables row-by-row
    instead of overwriting one file with the other. A blind file-copy sync
    was tried before and removed: if a push ever failed (network blip, or a
    race with another machine pushing first), the next pull would silently
    discard that machine's local-only upload records — causing the exact
    duplicate uploads this feature exists to prevent. Merging is additive
    only, so a failed push never loses local state.
    """

    _MAX_PUSH_ATTEMPTS = 5

    def __init__(self, repo_url: str, state_db_path: Path, branch: str = "main") -> None:
        self.repo_url = repo_url
        self.state_db_path = state_db_path
        self.branch = branch
        self.sync_dir = state_db_path.parent / ".state_sync"

    def _run_git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(self.sync_dir), *args],
            capture_output=True, text=True, check=False,
        )

    def _clone_or_fetch(self) -> bool:
        """Ensure sync_dir's working tree matches origin/<branch>. Returns
        False (with a warning logged) if git isn't available or the repo
        can't be reached."""
        if (self.sync_dir / ".git").exists():
            result = self._run_git("fetch", "origin", self.branch)
            if result.returncode != 0:
                if "couldn't find remote ref" in result.stderr.lower():
                    # Brand-new repo (e.g. straight off `gh repo create`) —
                    # nobody has pushed yet, so the branch doesn't exist
                    # upstream. Not fatal: keep whatever local branch state
                    # we have and let push() create the branch remotely.
                    log.info("state-sync: remote has no '%s' branch yet", self.branch)
                    self._run_git("checkout", "-B", self.branch)
                    return True
                log.warning("state-sync: fetch failed (rc=%d): %s",
                            result.returncode, _redact(result.stderr.strip())[:300])
                return False
            result = self._run_git("reset", "--hard", f"origin/{self.branch}")
            if result.returncode != 0:
                log.warning("state-sync: reset failed (rc=%d): %s",
                            result.returncode, _redact(result.stderr.strip())[:300])
                return False
            return True

        log.info("state-sync: cloning %s", _redact(self.repo_url))
        self.sync_dir.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--branch", self.branch, "--", self.repo_url, str(self.sync_dir)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode == 0:
            return True
        # Branch doesn't exist yet on a brand-new repo — clone default and
        # create it locally; push() will create it on the remote.
        result = subprocess.run(
            ["git", "clone", "--", self.repo_url, str(self.sync_dir)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            log.warning("state-sync: clone failed (rc=%d): %s",
                        result.returncode, _redact(result.stderr.strip())[:300])
            return False
        self._run_git("checkout", "-B", self.branch)
        return True

    @staticmethod
    def _ensure_schema(db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _merge_into_local(self, remote_db: Path) -> None:
        """Merge rows from ``remote_db`` into the local state.db. New rows
        are always added; on a (sha256, target) conflict, the remote row
        only overwrites local when it proves a successful upload the local
        row doesn't already record (never downgrades a good status)."""
        self._ensure_schema(remote_db)
        self._ensure_schema(self.state_db_path)
        conn = sqlite3.connect(str(self.state_db_path))
        try:
            conn.execute("ATTACH DATABASE ? AS remote", (str(remote_db),))
            # The ORDER BY is load-bearing, not a stray leftover: SQLite's
            # parser otherwise misreads the bare `ON` after `FROM remote.x`
            # as starting a JOIN and fails with "near DO: syntax error".
            conn.execute(
                """INSERT INTO processed (sha256, target, source, flow_id, uploaded_at, status)
                   SELECT sha256, target, source, flow_id, uploaded_at, status
                   FROM remote.processed
                   ORDER BY sha256, target
                   ON CONFLICT(sha256, target) DO UPDATE SET
                     source = excluded.source,
                     flow_id = excluded.flow_id,
                     uploaded_at = excluded.uploaded_at,
                     status = excluded.status
                   WHERE excluded.status IN ('uploaded', 'report_ready', 'vaulted')
                     AND processed.status NOT IN ('uploaded', 'report_ready', 'vaulted')"""
            )
            conn.execute(
                """INSERT INTO source_cursor (source, cursor, updated_at)
                   SELECT source, cursor, updated_at FROM remote.source_cursor
                   ORDER BY source
                   ON CONFLICT(source) DO UPDATE SET
                     cursor = excluded.cursor,
                     updated_at = excluded.updated_at
                   WHERE excluded.updated_at > source_cursor.updated_at"""
            )
            conn.commit()
        finally:
            conn.execute("DETACH DATABASE remote")
            conn.close()

    def pull(self) -> None:
        """Fetch the remote repo and merge its state.db into the local one."""
        if not self._clone_or_fetch():
            return
        remote_db = self.sync_dir / "state.db"
        if not remote_db.exists():
            log.info("state-sync: no remote state.db yet (first run)")
            return
        self._merge_into_local(remote_db)
        log.info("state-sync: merged remote state.db into local")

    def push(self) -> None:
        """Merge in anything pushed since our pull, then push the local
        (now-superset) state.db back. Retries on a losing race against
        another machine's push."""
        if not self.state_db_path.exists():
            log.warning("state-sync: local state.db not found, skipping push")
            return

        for attempt in range(1, self._MAX_PUSH_ATTEMPTS + 1):
            if not self._clone_or_fetch():
                return
            remote_db = self.sync_dir / "state.db"
            if remote_db.exists():
                self._merge_into_local(remote_db)

            shutil.copy2(str(self.state_db_path), str(remote_db))
            self._run_git("add", "state.db")

            diff = self._run_git("diff", "--cached", "--quiet")
            if diff.returncode == 0:
                log.info("state-sync: no changes to push")
                return

            hostname = platform.node() or "unknown"
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            commit = self._run_git("commit", "-m", f"sync {hostname} {ts}")
            if commit.returncode != 0:
                log.warning("state-sync: commit failed: %s", _redact(commit.stderr.strip())[:300])
                return

            result = self._run_git("push", "origin", f"HEAD:{self.branch}")
            if result.returncode == 0:
                log.info("state-sync: pushed state.db to remote")
                return
            log.info("state-sync: push rejected (attempt %d/%d): %s — retrying against latest remote",
                      attempt, self._MAX_PUSH_ATTEMPTS, _redact(result.stderr.strip())[:300])

        log.warning("state-sync: push failed after %d attempts — will retry next run",
                     self._MAX_PUSH_ATTEMPTS)

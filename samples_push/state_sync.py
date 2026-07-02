from __future__ import annotations

import logging
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


log = logging.getLogger(__name__)


class StateSync:
    """Syncs state.db via a private Git repo for multi-machine dedup."""

    def __init__(self, repo_url: str, state_db_path: Path) -> None:
        self.repo_url = repo_url
        self.state_db_path = state_db_path
        self.sync_dir = state_db_path.parent / ".state_sync"

    def pull(self) -> None:
        """Clone or pull the remote repo, then copy state.db locally."""
        if (self.sync_dir / ".git").exists():
            log.info("state-sync: pulling latest from remote")
            result = subprocess.run(
                ["git", "-C", str(self.sync_dir), "pull", "--ff-only"],
                capture_output=True, text=True, check=False,
            )
            if result.returncode != 0:
                log.warning("state-sync: pull failed (rc=%d): %s",
                            result.returncode, result.stderr.strip()[:300])
                return
        else:
            log.info("state-sync: cloning %s", self.repo_url)
            self.sync_dir.parent.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", self.repo_url, str(self.sync_dir)],
                capture_output=True, text=True, check=False,
            )
            if result.returncode != 0:
                log.warning("state-sync: clone failed (rc=%d): %s",
                            result.returncode, result.stderr.strip()[:300])
                return

        remote_db = self.sync_dir / "state.db"
        if remote_db.exists():
            shutil.copy2(str(remote_db), str(self.state_db_path))
            log.info("state-sync: pulled state.db (%d bytes)", remote_db.stat().st_size)
        else:
            log.info("state-sync: no remote state.db yet (first run)")

    def push(self) -> None:
        """Copy local state.db to the repo and push."""
        if not (self.sync_dir / ".git").exists():
            log.warning("state-sync: sync dir not initialized, skipping push")
            return

        if not self.state_db_path.exists():
            log.warning("state-sync: state.db not found, skipping push")
            return

        shutil.copy2(str(self.state_db_path), str(self.sync_dir / "state.db"))

        hostname = platform.node() or "unknown"
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        msg = f"sync {hostname} {ts}"

        subprocess.run(
            ["git", "-C", str(self.sync_dir), "add", "state.db"],
            capture_output=True, text=True, check=False,
        )

        result = subprocess.run(
            ["git", "-C", str(self.sync_dir), "diff", "--cached", "--quiet"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode == 0:
            log.info("state-sync: no changes to push")
            return

        result = subprocess.run(
            ["git", "-C", str(self.sync_dir), "commit", "-m", msg],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            log.warning("state-sync: commit failed: %s", result.stderr.strip()[:300])
            return

        result = subprocess.run(
            ["git", "-C", str(self.sync_dir), "push"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            log.warning("state-sync: push failed (rc=%d): %s — will retry next run",
                        result.returncode, result.stderr.strip()[:300])
        else:
            log.info("state-sync: pushed state.db to remote")

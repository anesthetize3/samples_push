from __future__ import annotations

import io
import logging
import re
import time
from typing import Iterator

import pyzipper

from ..models import Sample
from .base import Source


log = logging.getLogger(__name__)

HASHLIST_URL = "https://virusshare.com/hashfiles/VirusShare_{idx:05d}.md5"
DOWNLOAD_URL = "https://virusshare.com/apiv2/download"

# Starting cursor when nothing in state yet. Latest as of 2026-06.
DEFAULT_START_INDEX = 499
# Rate-limit buffer between API hits (seconds).
REQUEST_DELAY = 1.0

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")


class VirusShareSource(Source):
    """VirusShare: download recent samples by MD5 from a published hash list.

    Behavior:
      1. Pick a hash list index: env override > state cursor > default.
      2. Fetch VirusShare_NNNNN.md5; if 404, walk backward to find latest.
      3. Take the last `limit` MD5s (newest entries in the torrent).
      4. Download each via /apiv2/download (password-protected zip, pw 'infected').
      5. Advance cursor to the highest list index successfully fetched.
    """

    name = "virusshare"
    ZIP_PASSWORD = b"infected"

    def __init__(self, config) -> None:
        super().__init__(config)
        self.api_key = config.env["VIRUSSHARE_API_KEY"].strip()
        idx_override = config.env.get("VIRUSSHARE_HASHLIST_INDEX", "").strip()
        self.index_override = int(idx_override) if idx_override.isdigit() else None
        # Set by pipeline before iter_new via attribute injection? No — keep self-contained.
        # We persist cursor via the pipeline's State, but Source has no state ref.
        # Workaround: stash a callable on config later if needed. For now, env-only.

    def iter_new(self, limit: int) -> Iterator[Sample]:
        idx = self._resolve_index()
        if idx is None:
            log.warning("VirusShare: no reachable hash list found")
            return
        hashes = self._fetch_hashlist(idx)
        if not hashes:
            log.warning("VirusShare: list %d empty", idx)
            return
        log.info("VirusShare: using hashlist %d (%d hashes), taking last %d",
                 idx, len(hashes), limit)
        yielded = 0
        for md5 in reversed(hashes):
            if yielded >= limit:
                return
            try:
                content, inner_name = self._download(md5)
            except Exception as e:
                log.warning("VirusShare download %s failed: %s", md5, e)
                continue
            sha256 = self.sha256_of(content)
            yield Sample(
                sha256=sha256,
                source=self.name,
                filename=inner_name or f"{sha256}.bin",
                content=content,
                metadata={"md5": md5, "hashlist_index": idx},
            )
            yielded += 1
            time.sleep(REQUEST_DELAY)

    def _resolve_index(self) -> int | None:
        if self.index_override is not None:
            return self.index_override
        # Walk forward from default to find the latest, then back if needed.
        idx = DEFAULT_START_INDEX
        for _ in range(50):
            resp = self.session.head(HASHLIST_URL.format(idx=idx + 1), timeout=30)
            if resp.status_code == 200:
                idx += 1
            else:
                break
        # Confirm `idx` itself exists; walk back if not.
        for _ in range(20):
            resp = self.session.head(HASHLIST_URL.format(idx=idx), timeout=30)
            if resp.status_code == 200:
                return idx
            idx -= 1
            if idx < 0:
                return None
        return None

    def _fetch_hashlist(self, idx: int) -> list[str]:
        url = HASHLIST_URL.format(idx=idx)
        resp = self.session.get(url, timeout=120)
        resp.raise_for_status()
        out: list[str] = []
        for line in resp.text.splitlines():
            line = line.strip()
            if _MD5_RE.match(line):
                out.append(line.lower())
        return out

    def _download(self, md5: str) -> tuple[bytes, str]:
        for attempt in range(3):
            resp = self.session.get(
                DOWNLOAD_URL,
                params={"apikey": self.api_key, "hash": md5},
                timeout=180,
            )
            if resp.status_code == 204:
                # Rate limited — back off then retry once.
                log.info("VirusShare 204 rate-limited, sleeping 5s")
                time.sleep(5.0)
                continue
            if resp.status_code == 404:
                raise RuntimeError("not found")
            resp.raise_for_status()
            ctype = resp.headers.get("Content-Type", "").lower()
            if "json" in ctype:
                raise RuntimeError(f"unexpected JSON: {resp.text[:200]}")
            if not resp.content:
                raise RuntimeError("empty body")
            return self._unwrap_zip(resp.content)
        raise RuntimeError("rate-limited after retries")

    def _unwrap_zip(self, data: bytes) -> tuple[bytes, str]:
        try:
            with pyzipper.AESZipFile(io.BytesIO(data)) as zf:
                zf.setpassword(self.ZIP_PASSWORD)
                names = [n for n in zf.namelist() if not n.endswith("/")]
                if not names:
                    raise RuntimeError("empty zip")
                return zf.read(names[0]), names[0]
        except (pyzipper.BadZipFile, RuntimeError):
            # Some hashes may be served raw (no zip). Fall through.
            return data, ""

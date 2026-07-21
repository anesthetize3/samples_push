from __future__ import annotations

import logging
from typing import Iterator

from ..models import Sample
from .base import Source


log = logging.getLogger(__name__)

API_URL = "https://malshare.com/api.php"


class MalShareSource(Source):
    name = "malshare"

    def __init__(self, config) -> None:
        super().__init__(config)
        self.api_key = config.env["MALSHARE_API_KEY"].strip()

    def iter_new(self, limit: int) -> Iterator[Sample]:
        resp = self.session.get(
            API_URL,
            params={"api_key": self.api_key, "action": "getlist"},
            timeout=60,
        )
        resp.raise_for_status()
        items = resp.json() or []
        skipped = sum(1 for i in items if (i.get("sha256") or "").lower() in self.skip_hashes)
        log.info("MalShare got %d hashes (%d already known, %d new)", len(items), skipped, len(items) - skipped)
        yielded = 0
        download_failed = 0
        too_small = 0
        for item in items:
            if yielded >= limit:
                return
            sha256 = (item.get("sha256") or "").lower()
            if not sha256:
                continue
            if sha256 in self.skip_hashes:
                continue
            try:
                content = self._download(sha256)
            except Exception as e:
                log.warning("MalShare download %s failed: %s", sha256, e)
                download_failed += 1
                continue
            yield Sample(
                sha256=sha256,
                source=self.name,
                filename=f"{sha256}.bin",
                content=content,
                metadata={"md5": item.get("md5"), "sha1": item.get("sha1")},
            )
            yielded += 1
        if download_failed or too_small:
            log.info("MalShare: %d download failures, %d too small", download_failed, too_small)

    def _download(self, sha256: str) -> bytes:
        resp = self.session.get(
            API_URL,
            params={"api_key": self.api_key, "action": "getfile", "hash": sha256},
            timeout=120,
        )
        resp.raise_for_status()
        if not resp.content or resp.content.startswith(b"Sample not found"):
            raise RuntimeError("sample not found")
        if len(resp.content) < 64:
            raise RuntimeError(f"sample too small ({len(resp.content)} bytes)")
        return resp.content

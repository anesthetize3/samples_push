from __future__ import annotations

import logging
from typing import Iterator

from ..models import Sample
from .base import Source


log = logging.getLogger(__name__)

LIST_URL = "https://virus.exchange/api/samples"
DOWNLOAD_URL = "https://virus.exchange/api/samples/{sha256}/download"


class VirusExchangeSource(Source):
    name = "vx"

    def __init__(self, config) -> None:
        super().__init__(config)
        key = config.env["VX_API_KEY"].strip()
        self.session.headers["Authorization"] = f"Bearer {key}"

    def iter_new(self, limit: int) -> Iterator[Sample]:
        resp = self.session.get(LIST_URL, params={"limit": limit}, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        items = payload.get("data") or payload.get("samples") or payload or []
        yielded = 0
        for item in items:
            if yielded >= limit:
                return
            sha256 = (item.get("sha256") or item.get("sha256_hash") or "").lower()
            if not sha256:
                continue
            try:
                content = self._download(sha256)
            except Exception as e:
                log.warning("VX download %s failed: %s", sha256, e)
                continue
            yield Sample(
                sha256=sha256,
                source=self.name,
                filename=item.get("name") or f"{sha256}.bin",
                content=content,
                metadata={
                    "type": item.get("type"),
                    "first_seen": item.get("first_seen"),
                    "tags": item.get("tags"),
                },
            )
            yielded += 1

    def _download(self, sha256: str) -> bytes:
        resp = self.session.get(
            DOWNLOAD_URL.format(sha256=sha256),
            timeout=180,
            allow_redirects=True,
        )
        resp.raise_for_status()
        if not resp.content:
            raise RuntimeError("empty body")
        return resp.content

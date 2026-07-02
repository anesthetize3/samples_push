from __future__ import annotations

import logging
import time
from typing import Iterator

from ..models import Sample
from .base import Source


log = logging.getLogger(__name__)

LIST_URL = "https://labs.inquest.net/api/dfi/list"
DOWNLOAD_URL = "https://labs.inquest.net/api/dfi/download"


class InquestSource(Source):
    name = "inquest"

    def __init__(self, config) -> None:
        super().__init__(config)
        key = config.env["INQUEST_API_KEY"].strip()
        # InQuest Labs accepts the key via Authorization: Basic <key>
        self.session.headers["Authorization"] = f"Basic {key}"

    def iter_new(self, limit: int) -> Iterator[Sample]:
        resp = self._get(LIST_URL, params={"limit": limit})
        resp.raise_for_status()
        payload = resp.json()
        items = payload.get("data") or []
        yielded = 0
        for item in items:
            if yielded >= limit:
                return
            sha256 = (item.get("sha256") or "").lower()
            if not sha256:
                continue
            try:
                content = self._download(sha256)
            except Exception as e:
                log.warning("InQuest download %s failed: %s", sha256, e)
                continue
            yield Sample(
                sha256=sha256,
                source=self.name,
                filename=item.get("file_name") or f"{sha256}.bin",
                content=content,
                metadata={
                    "classification": item.get("classification"),
                    "first_seen": item.get("first_seen"),
                    "len_code": item.get("len_code"),
                },
            )
            yielded += 1

    def _download(self, sha256: str) -> bytes:
        resp = self._get(DOWNLOAD_URL, params={"sha256": sha256})
        resp.raise_for_status()
        if not resp.content:
            raise RuntimeError("empty body")
        return resp.content

    def _get(self, url: str, params: dict):
        for attempt in range(3):
            resp = self.session.get(url, params=params, timeout=120)
            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", "5"))
                log.info("InQuest rate-limited, sleeping %ds", wait)
                time.sleep(wait)
                continue
            return resp
        return resp

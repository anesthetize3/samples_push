from __future__ import annotations

import logging
from typing import Iterator

from ..models import Sample
from .base import Source


log = logging.getLogger(__name__)

LIST_URL = "https://urlhaus-api.abuse.ch/v1/payloads/recent/"
DOWNLOAD_URL = "https://urlhaus-api.abuse.ch/downloads/sha256/{sha256}/"


class URLhausSource(Source):
    name = "urlhaus"

    def __init__(self, config) -> None:
        super().__init__(config)
        key = config.env["ABUSECH_API_KEY"].strip()
        self.session.headers["Auth-Key"] = key

    def iter_new(self, limit: int) -> Iterator[Sample]:
        resp = self.session.post(LIST_URL, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("query_status") != "ok":
            log.warning("URLhaus list status=%s", payload.get("query_status"))
            return
        items = payload.get("payloads") or []
        yielded = 0
        for item in items:
            if yielded >= limit:
                return
            sha256 = (item.get("sha256_hash") or "").lower()
            if not sha256:
                continue
            try:
                content = self._download(sha256)
            except Exception as e:
                log.warning("URLhaus download %s failed: %s", sha256, e)
                continue
            yield Sample(
                sha256=sha256,
                source=self.name,
                filename=item.get("file_name") or f"{sha256}.bin",
                content=content,
                metadata={
                    "signature": item.get("signature"),
                    "firstseen": item.get("firstseen"),
                    "file_type": item.get("file_type"),
                },
            )
            yielded += 1

    def _download(self, sha256: str) -> bytes:
        resp = self.session.get(DOWNLOAD_URL.format(sha256=sha256), timeout=120)
        resp.raise_for_status()
        if not resp.content:
            raise RuntimeError("empty body")
        return resp.content

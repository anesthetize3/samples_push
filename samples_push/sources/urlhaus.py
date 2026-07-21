from __future__ import annotations

import io
import logging
import zipfile
from typing import Iterator

from ..models import Sample
from .base import Source


log = logging.getLogger(__name__)

LIST_URL = "https://urlhaus-api.abuse.ch/v1/payloads/recent/"
DOWNLOAD_URL = "https://urlhaus-api.abuse.ch/v1/download/{sha256}/"


class URLhausSource(Source):
    name = "urlhaus"

    def __init__(self, config) -> None:
        super().__init__(config)
        key = config.env.get("ABUSECH_API_KEY", "").strip()
        if key:
            self.session.headers["Auth-Key"] = key
        self.min_size = int(config.env.get("URLHAUS_MIN_FILE_SIZE", "256").strip())

    def iter_new(self, limit: int) -> Iterator[Sample]:
        resp = self.session.get(LIST_URL, timeout=60)
        resp.raise_for_status()
        log.debug("urlhaus response: %s", resp.text[:200])

        if resp.text.strip().startswith("ERROR"):
            log.error("URLhaus API error: %s (check your ABUSECH_API_KEY)", resp.text.strip())
            return

        try:
            payload = resp.json()
        except Exception as e:
            log.warning("URLhaus response parse failed: %s (body: %s)", e, resp.text[:500])
            return
        if payload.get("query_status") != "ok":
            log.warning("URLhaus list status=%s", payload.get("query_status"))
            return
        items = payload.get("payloads") or []
        skipped = sum(1 for i in items if (i.get("sha256_hash") or "").lower() in self.skip_hashes)
        log.info("URLhaus got %d payloads (%d already known, %d new)", len(items), skipped, len(items) - skipped)
        yielded = 0
        for item in items:
            if yielded >= limit:
                return
            sha256 = (item.get("sha256_hash") or "").lower()
            if not sha256:
                continue
            if sha256 in self.skip_hashes:
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

        try:
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                files = [f for f in zf.namelist() if not f.endswith('/')]
                if not files:
                    raise RuntimeError("empty zip")
                data = zf.read(files[0])
                if not data:
                    raise RuntimeError("empty file in zip")
                return data
        except (zipfile.BadZipFile, RuntimeError) as e:
            if isinstance(e, RuntimeError) and "empty" in str(e):
                raise
            log.debug("urlhaus: not a zip, treating as raw file (%d bytes)", len(resp.content))
            if len(resp.content) < self.min_size:
                log.warning("urlhaus: file below minimum size (%d < %d bytes)", len(resp.content), self.min_size)
                raise RuntimeError(f"file too small ({len(resp.content)} bytes, min: {self.min_size})")
            return resp.content

from __future__ import annotations

import gzip
import logging
from typing import Iterator

from ..models import Sample
from .base import Source


log = logging.getLogger(__name__)

LIST_URL = "https://www.hybrid-analysis.com/api/v2/feed/latest"
DOWNLOAD_URL = "https://www.hybrid-analysis.com/api/v2/overview/{sha256}/sample"


class HybridAnalysisSource(Source):
    """Hybrid Analysis (Falcon Sandbox) recent feed → sample download.

    Note: a default free API key is "restricted" and cannot download samples.
    Requires the key to be upgraded to "default" auth level (request via
    https://www.hybrid-analysis.com/ profile page).
    """

    name = "hybrid"

    def __init__(self, config) -> None:
        super().__init__(config)
        key = config.env["HYBRID_API_KEY"].strip()
        self.session.headers["api-key"] = key
        self.session.headers["User-Agent"] = "Falcon Sandbox"

    def iter_new(self, limit: int) -> Iterator[Sample]:
        resp = self.session.get(LIST_URL, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("status") and payload.get("status") != "ok":
            log.warning("HybridAnalysis feed status=%s", payload.get("status"))
            return
        items = payload.get("data") or []
        # Keep only entries flagged malicious/suspicious — feed includes benign too.
        items = [
            i for i in items
            if (i.get("verdict") or "").lower() in {"malicious", "suspicious"}
        ]
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
                log.warning("HybridAnalysis download %s failed: %s", sha256, e)
                continue
            yield Sample(
                sha256=sha256,
                source=self.name,
                filename=item.get("submitname") or f"{sha256}.bin",
                content=content,
                metadata={
                    "verdict": item.get("verdict"),
                    "threatlevel": item.get("threatlevel"),
                    "vx_family": item.get("vx_family"),
                    "type": item.get("type"),
                    "submit_name": item.get("submitname"),
                },
            )
            yielded += 1

    def _download(self, sha256: str) -> bytes:
        resp = self.session.get(
            DOWNLOAD_URL.format(sha256=sha256),
            timeout=180,
        )
        if resp.status_code == 403:
            raise RuntimeError(
                "403 forbidden — your API key likely lacks 'default' auth level "
                "(restricted keys can't download). Upgrade via Hybrid Analysis profile."
            )
        if resp.status_code == 404:
            raise RuntimeError("not available")
        resp.raise_for_status()
        if not resp.content:
            raise RuntimeError("empty body")
        # Body is gzip-compressed sample bytes.
        try:
            return gzip.decompress(resp.content)
        except (OSError, gzip.BadGzipFile):
            return resp.content

from __future__ import annotations

import abc
import hashlib
from typing import Iterator

import requests

from ..config import Config
from ..models import Sample


class Source(abc.ABC):
    name: str = "base"

    def __init__(self, config: Config) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "samples_push/0.1"

    @abc.abstractmethod
    def iter_new(self, limit: int) -> Iterator[Sample]:
        """Yield up to `limit` fresh samples. Caller handles dedup against state."""

    @staticmethod
    def sha256_of(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

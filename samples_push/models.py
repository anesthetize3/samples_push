from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Sample:
    sha256: str
    source: str
    filename: str
    content: bytes
    metadata: dict = field(default_factory=dict)

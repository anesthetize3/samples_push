from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


# Source registry: short_id -> (module path, class name, env keys it needs)
SOURCE_REGISTRY: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "bazaar":  ("samples_push.sources.malwarebazaar",   "MalwareBazaarSource", ("ABUSECH_API_KEY",)),
    "urlhaus": ("samples_push.sources.urlhaus",         "URLhausSource",       ("ABUSECH_API_KEY",)),
    "malshare": ("samples_push.sources.malshare",       "MalShareSource",      ("MALSHARE_API_KEY",)),
    "vx":      ("samples_push.sources.virusexchange",   "VirusExchangeSource", ("VX_API_KEY",)),
    "inquest": ("samples_push.sources.inquest",         "InquestSource",       ("INQUEST_API_KEY",)),
    "virusshare": ("samples_push.sources.virusshare",   "VirusShareSource",    ("VIRUSSHARE_API_KEY",)),
    "hybrid":  ("samples_push.sources.hybrid",          "HybridAnalysisSource", ("HYBRID_API_KEY",)),
    "thezoo":  ("samples_push.sources.thezoo",          "TheZooSource",        ()),
}

# Sources used when --sources is not given. theZoo is excluded by default
# because its first run clones a multi-GB repo over Git LFS.
DEFAULT_SOURCES: tuple[str, ...] = (
    "bazaar", "urlhaus", "malshare", "vx", "inquest", "virusshare", "hybrid",
)


def _platform_data_root() -> Path:
    """Per-user data directory, OS-appropriate.

    Windows: %LOCALAPPDATA%\\samples_push
    macOS:   ~/Library/Application Support/samples_push
    Linux:   $XDG_DATA_HOME/samples_push  (default ~/.local/share/samples_push)
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "samples_push"
    elif sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "samples_push"
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        if xdg:
            return Path(xdg) / "samples_push"
        return Path.home() / ".local" / "share" / "samples_push"
    return Path.home() / ".samples_push"


def default_vault_path() -> Path:
    return _platform_data_root() / "vault"


def default_thezoo_cache() -> Path:
    return _platform_data_root() / "thezoo-cache"


@dataclass
class Config:
    filescan_api_key: str
    filescan_auth_token: str
    filescan_staging_api_key: str
    filescan_base_url: str
    env: dict[str, str]

    @classmethod
    def load(cls) -> "Config":
        data_root = _platform_data_root()
        data_root.mkdir(parents=True, exist_ok=True)
        env_path = data_root / ".env"
        load_dotenv(env_path)
        return cls(
            filescan_api_key=os.environ.get("FILESCAN_API_KEY", "").strip(),
            filescan_auth_token=os.environ.get("FILESCAN_AUTH_TOKEN", "").strip(),
            filescan_staging_api_key=os.environ.get(
                "FILESCAN_STAGING_API_KEY", ""
            ).strip(),
            filescan_base_url=os.environ.get(
                "FILESCAN_BASE_URL", "https://www.filescan.io"
            ).strip().rstrip("/"),
            env=dict(os.environ),
        )

    def has_keys(self, keys: tuple[str, ...]) -> bool:
        return all(self.env.get(k, "").strip() for k in keys)

    def key_for_target(self, target: str) -> str:
        """Pick the appropriate filescan API key for ``target``.

        Staging URLs use ``FILESCAN_STAGING_API_KEY`` when set, otherwise
        fall back to the prod key. Anything else uses the prod key.
        """
        if "staging.filescan.io" in target and self.filescan_staging_api_key:
            return self.filescan_staging_api_key
        return self.filescan_api_key

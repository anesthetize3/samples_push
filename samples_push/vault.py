from __future__ import annotations

import io
import threading
from pathlib import Path

import pyzipper

PASSWORD = b"infected"

# Folder-name prefixes that indicate a cloud-sync root we must NOT write
# malware into. Match is case-insensitive on any ancestor path component.
CLOUD_SYNC_PREFIXES = (
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "icloud",
    "icloud drive",
    "nextcloud",
    "owncloud",
    "pcloud",
    "box sync",
    "mega",
    "syncthing",
)


class CloudSyncVaultError(RuntimeError):
    pass


# Backwards-compatible alias for any external imports.
OneDriveVaultError = CloudSyncVaultError


def assert_vault_safe(path: Path) -> None:
    """Refuse vault paths that live under any cloud-sync folder."""
    resolved = path.expanduser().resolve()
    for part in resolved.parts:
        lower = part.lower()
        for prefix in CLOUD_SYNC_PREFIXES:
            if lower.startswith(prefix):
                raise CloudSyncVaultError(
                    f"Vault path '{resolved}' is inside a cloud-sync folder "
                    f"('{part}'). Pick a non-synced location, e.g. "
                    f"~/.local/share/samples_push/vault on Linux or "
                    f"%LOCALAPPDATA%\\samples_push\\vault on Windows."
                )


class EncryptedVault:
    """One AES-encrypted zip per source. Append-only, in-memory I/O."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        assert_vault_safe(self.root)
        self.samples_dir = self.root / "samples"
        self.samples_dir.mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(parents=True, exist_ok=True)
        self._locks: dict[str, threading.Lock] = {}

    def _zip_path(self, source: str) -> Path:
        return self.samples_dir / f"{source}.zip"

    def _lock_for(self, source: str) -> threading.Lock:
        return self._locks.setdefault(source, threading.Lock())

    def _member_name(self, sha256: str, filename: str) -> str:
        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[1].lower()
            if len(ext) > 8:
                ext = ""
        return f"{sha256}{ext}"

    def has(self, source: str, sha256: str) -> bool:
        zp = self._zip_path(source)
        if not zp.exists():
            return False
        with self._lock_for(source):
            with pyzipper.AESZipFile(zp, "r") as zf:
                zf.setpassword(PASSWORD)
                prefix = sha256.lower()
                for name in zf.namelist():
                    if name.lower().startswith(prefix):
                        return True
        return False

    def add(self, source: str, sha256: str, filename: str, data: bytes) -> str:
        member = self._member_name(sha256, filename)
        zp = self._zip_path(source)
        with self._lock_for(source):
            mode = "a" if zp.exists() else "w"
            with pyzipper.AESZipFile(
                zp,
                mode,
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as zf:
                zf.setpassword(PASSWORD)
                if member in zf.namelist():
                    return member
                zf.writestr(member, data)
        return member

    def read(self, source: str, sha256: str) -> tuple[str, bytes]:
        zp = self._zip_path(source)
        with self._lock_for(source):
            with pyzipper.AESZipFile(zp, "r") as zf:
                zf.setpassword(PASSWORD)
                prefix = sha256.lower()
                for name in zf.namelist():
                    if name.lower().startswith(prefix):
                        return name, zf.read(name)
        raise KeyError(f"{sha256} not found in {source} vault")

    def open_stream(self, source: str, sha256: str) -> io.BytesIO:
        name, data = self.read(source, sha256)
        bio = io.BytesIO(data)
        bio.name = name
        return bio

    def list_all(self) -> list[tuple[str, str, str]]:
        """List all (source, sha256, filename) tuples across all vault zips."""
        results = []
        for zp in self.samples_dir.glob("*.zip"):
            if zp.stem.endswith("_backup"):
                continue
            source = zp.stem
            with self._lock_for(source):
                try:
                    with pyzipper.AESZipFile(zp, "r") as zf:
                        zf.setpassword(PASSWORD)
                        for name in zf.namelist():
                            sha = name.split(".")[0] if "." in name else name
                            results.append((source, sha, name))
                except Exception:
                    continue
        return results

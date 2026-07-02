from __future__ import annotations

import logging
import subprocess
import zipfile
from pathlib import Path
from typing import Iterator

from ..config import default_thezoo_cache
from ..models import Sample
from .base import Source


log = logging.getLogger(__name__)

REPO_URL = "https://github.com/ytisf/theZoo.git"

# Source code extensions to skip (not useful for malware analysis on FileScan)
SOURCE_CODE_EXTENSIONS = frozenset({
    ".java", ".py", ".c", ".cpp", ".h", ".cs", ".go", ".rs",
    ".rb", ".pl", ".php", ".swift", ".kt", ".scala", ".groovy",
    ".ts", ".tsx", ".jsx", ".js", ".coffee",
    ".asm", ".s", ".inc",
    ".md", ".txt", ".rst", ".log", ".cfg", ".ini", ".yaml", ".yml",
    ".json", ".xml", ".csv", ".html", ".htm", ".css",
    ".gitignore", ".gitattributes", ".editorconfig",
    ".sln", ".csproj", ".pom", ".gradle", ".makefile",
    ".sh", ".bash",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
})


class TheZooSource(Source):
    """Static curated repo. Clones once into a non-OneDrive cache, then yields
    one inner-sample per password-protected zip under malware/Binaries/."""

    name = "thezoo"

    def __init__(self, config) -> None:
        super().__init__(config)
        self.cache = default_thezoo_cache()

    def _ensure_repo(self) -> Path:
        if (self.cache / ".git").exists():
            log.info("theZoo: pulling latest")
            result = subprocess.run(
                ["git", "-C", str(self.cache), "pull", "--ff-only"],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                log.warning("theZoo: git pull failed (rc=%d): %s",
                            result.returncode, result.stderr.strip()[:500])
            return self.cache
        log.info("theZoo: cloning into %s", self.cache)
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", REPO_URL, str(self.cache)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git clone of theZoo failed (rc={result.returncode}): "
                f"{result.stderr.strip()[:1000]}"
            )
        return self.cache

    def iter_new(self, limit: int) -> Iterator[Sample]:
        repo = self._ensure_repo()
        bin_root = repo / "malware" / "Binaries"
        if not bin_root.exists():
            log.warning("theZoo: %s not found", bin_root)
            return
        defender_warned = False
        yielded = 0
        for sub in sorted(bin_root.iterdir()):
            if yielded >= limit:
                return
            if not sub.is_dir():
                continue
            zips = list(sub.glob("*.zip"))
            pass_files = list(sub.glob("*.pass"))
            if not zips:
                # Likely Defender quarantined the .zip immediately after clone.
                # Other artifacts (.md5/.pass/.shasum) survive, so detect by their presence.
                if pass_files and not defender_warned:
                    log.error(
                        "theZoo: zip files missing from %s. "
                        "Windows Defender (or another AV) is most likely deleting them on write. "
                        "Run as admin once: Add-MpPreference -ExclusionPath \"%%LOCALAPPDATA%%\\samples_push\" "
                        "then delete the cache and retry.",
                        sub.parent,
                    )
                    defender_warned = True
                continue
            if not pass_files:
                continue

            # Read password from .pass file (theZoo standard: "infected")
            # Try multiple passwords in case of legacy/corrupted entries
            password_text = pass_files[0].read_text(errors="replace").strip()
            passwords_to_try = [
                password_text.encode() if password_text else b"infected",
                b"infected",  # Fallback to default
                b"",  # Try empty password
            ]
            # Remove duplicates while preserving order
            passwords_to_try = list(dict.fromkeys(passwords_to_try))

            for zp in zips:
                entries = None
                for pwd_idx, pwd in enumerate(passwords_to_try):
                    try:
                        entries = self._extract_all(zp, pwd)
                        break  # Success
                    except Exception:
                        if pwd_idx == len(passwords_to_try) - 1:
                            # Last attempt failed, log once
                            log.debug("theZoo: %s extract failed (tried %d passwords)",
                                     zp.name, len(passwords_to_try))
                        continue

                if entries is None:
                    continue

                for inner_name, content in entries:
                    sha256 = self.sha256_of(content)
                    yield Sample(
                        sha256=sha256,
                        source=self.name,
                        filename=inner_name or f"{sha256}.bin",
                        content=content,
                        metadata={"family_dir": sub.name, "archive": zp.name},
                    )
                    yielded += 1
                    if yielded >= limit:
                        return

    def _extract_all(self, zp: Path, password: bytes) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        with zipfile.ZipFile(zp) as zf:
            zf.setpassword(password)
            for info in zf.infolist():
                if info.is_dir():
                    continue
                filename = Path(info.filename).name
                ext = Path(filename).suffix.lower()
                if ext in SOURCE_CODE_EXTENSIONS:
                    log.debug("theZoo: skip source file %s!%s", zp.name, filename)
                    continue
                try:
                    data = zf.read(info)
                except RuntimeError:
                    raise
                except Exception as e:
                    log.debug("theZoo: read %s!%s failed: %s", zp.name, info.filename, e)
                    continue
                if not data:
                    continue
                out.append((filename, data))
        if not out:
            raise RuntimeError("empty zip or no binary files")
        return out

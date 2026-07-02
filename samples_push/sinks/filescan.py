from __future__ import annotations

import json
import base64
import logging
import time
from pathlib import Path

import requests


log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://www.filescan.io"
STAGING_BASE_URL = "https://staging.filescan.io"

# Backoff schedule for transient 429s (queue-full, rate-limit). Total ~3.5 min.
RETRY_BACKOFFS = (15, 45, 120)


class FilescanError(RuntimeError):
    pass


class FilescanQueueFull(FilescanError):
    """Filescan analysis queue is full and persisted across retries."""


class FilescanSink:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = 120,
        cookies_file: str | None = None,
        auth_token: str | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.upload_url = f"{self.base_url}/api/scan/file"
        self.report_url = f"{self.base_url}/api/scan/{{flow_id}}/report"
        self.timeout = timeout
        self.session = requests.Session()
        self.auth_method = None

        # Add browser-like headers to match UI request
        self._set_browser_headers()

        # Priority: auth_token (.env) > cookies file > api_key
        if auth_token:
            self._set_auth_token(auth_token)
            self.auth_method = "auth token (FILESCAN_AUTH_TOKEN)"
            log.info("FilescanSink initialized with auth method: %s", self.auth_method)
            return

        if cookies_file:
            if self._load_cookies(cookies_file):
                self.auth_method = f"cookies ({cookies_file})"
                return

        # Fallback to API key
        if api_key:
            self._set_api_key_auth(api_key)
            self.auth_method = "API key"
        else:
            raise ValueError("Either auth_token, api_key, or cookies_file must be provided")

        log.info("FilescanSink initialized with auth method: %s", self.auth_method)

    def _set_browser_headers(self) -> None:
        """Add browser-like headers to match UI request format."""
        self.session.headers.update({
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/scan",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        })

    def _set_auth_token(self, token: str) -> None:
        """Set authorization using browser auth token (JWT from DevTools).
        Requires api_key in X-Api-Key for API access + auth token for account identity."""
        token = token.strip()
        if token.startswith("Bearer "):
            token = token[7:]
        self.session.headers["Authorization"] = f"Bearer {token}"
        if self.api_key:
            self.session.headers["X-Api-Key"] = self.api_key
        self._validate_token_type(token)

    def _load_cookies(self, cookies_file: str) -> bool:
        """
        Load cookies from file and apply to session.
        Supports multiple formats:
        - Simple JSON: {"name": "value", ...}
        - Cookie array: {"url": "...", "cookies": [{name, value, ...}, ...]}
        - Netscape/curl format
        Returns True if cookies loaded successfully, False otherwise.
        """
        file_path = Path(cookies_file).expanduser()
        if not file_path.exists():
            log.warning("Cookies file not found: %s", file_path)
            return False

        try:
            with open(file_path) as f:
                content = f.read().strip()

            cookies_dict = {}

            # Try JSON format first
            if content.startswith("{"):
                data = json.loads(content)

                # Format 1: Array format with metadata (Cookie Editor export)
                if isinstance(data, dict) and "cookies" in data and isinstance(data["cookies"], list):
                    for cookie in data["cookies"]:
                        if isinstance(cookie, dict) and "name" in cookie and "value" in cookie:
                            name = cookie["name"]
                            value = cookie["value"]
                            # Remove extra quotes if present (from some exports)
                            if value.startswith('"') and value.endswith('"'):
                                value = value[1:-1]
                            cookies_dict[name] = value
                    log.info("Loaded %d cookies from array format: %s", len(cookies_dict), file_path)
                    self.session.cookies.update(cookies_dict)
                    return True

                # Format 2: Simple JSON (flat key-value pairs)
                if isinstance(data, dict) and "cookies" not in data and "url" not in data:
                    cookies_dict = data
                    log.info("Loaded %d cookies from JSON format: %s", len(cookies_dict), file_path)
                    self.session.cookies.update(cookies_dict)
                    return True

            # Try Netscape format (curl export)
            if content.startswith("#"):
                cookies_dict = self._parse_netscape_cookies(content)
                self.session.cookies.update(cookies_dict)
                log.info("Loaded %d cookies from Netscape format: %s", len(cookies_dict), file_path)
                return True

            log.warning("Unknown cookie file format in: %s", file_path)
            return False

        except json.JSONDecodeError as e:
            log.error("Failed to parse cookies file: %s", e)
            return False
        except Exception as e:
            log.error("Error loading cookies: %s", e)
            return False

    @staticmethod
    def _parse_netscape_cookies(content: str) -> dict[str, str]:
        """Parse Netscape/curl format cookie file."""
        cookies = {}
        for line in content.split("\n"):
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                name = parts[5]
                value = parts[6]
                cookies[name] = value
        return cookies

    def _set_api_key_auth(self, api_key: str) -> None:
        """Set authorization using API key (Bearer token format)."""
        if api_key.startswith("Bearer "):
            self.session.headers["Authorization"] = api_key
            token = api_key[7:]
        else:
            token = api_key
            self.session.headers["Authorization"] = f"Bearer {api_key}"

        self.session.headers["X-Api-Key"] = api_key
        self._validate_token_type(token)

    @staticmethod
    def _validate_token_type(token: str) -> None:
        """Validate JWT token type for leaderboard recording."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                log.warning("filescan token format invalid (expected JWT with 3 parts)")
                return

            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding

            data = json.loads(base64.urlsafe_b64decode(payload))
            token_type = data.get("type", "unknown")

            if token_type == "api_docs_access":
                log.debug("filescan token type: api_docs_access (leaderboard tracking enabled)")
            else:
                log.warning(
                    "filescan token type is '%s' (not 'api_docs_access') — "
                    "uploads may not appear on leaderboard. "
                    "Use --cookies FILE (browser cookies have proper token type) "
                    "or contact FileScan to upgrade your API key.",
                    token_type
                )
        except Exception as e:
            log.debug("filescan token validation skipped: %s", e)

    def upload(self, filename: str, content: bytes) -> str:
        last_detail = ""
        for attempt, backoff in enumerate((0,) + RETRY_BACKOFFS):
            if backoff:
                log.info("filescan retry in %ds (attempt %d/%d)",
                         backoff, attempt, len(RETRY_BACKOFFS))
                time.sleep(backoff)

            files = {"file": (filename, content, "application/octet-stream")}
            headers = {"sourceid": "samples_push"}
            try:
                resp = self.session.post(
                    self.upload_url,
                    files=files,
                    headers=headers,
                    timeout=self.timeout
                )
            except requests.RequestException as e:
                last_detail = str(e)
                log.warning("filescan upload network error: %s", e)
                continue

            if resp.status_code == 429:
                last_detail = resp.text[:300]
                wait = self._retry_after(resp)
                if wait is not None and wait > 0:
                    log.info("filescan 429 (queue-full); honoring Retry-After=%ds", wait)
                    time.sleep(wait)
                continue

            if resp.status_code >= 500:
                last_detail = f"HTTP {resp.status_code} {resp.text[:200]}"
                log.warning("filescan upload %s: %s", resp.status_code, last_detail)
                continue

            if resp.status_code >= 400:
                raise FilescanError(
                    f"filescan upload failed: HTTP {resp.status_code} {resp.text[:300]}"
                )

            data = resp.json()
            flow_id = data.get("flow_id") or data.get("flowId") or data.get("id")
            if not flow_id:
                raise FilescanError(f"filescan response missing flow_id: {data}")
            log.debug("filescan accepted %s -> flow_id=%s", filename, flow_id)
            return flow_id

        raise FilescanQueueFull(
            f"filescan upload still failing after {len(RETRY_BACKOFFS)} retries: {last_detail}"
        )

    @staticmethod
    def _retry_after(resp: requests.Response) -> int | None:
        raw = resp.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return max(0, int(raw))
        except ValueError:
            return None

    def poll_report(
        self,
        flow_id: str,
        max_wait: int = 300,
        interval: int = 10,
    ) -> dict:
        url = self.report_url.format(flow_id=flow_id)
        deadline = time.time() + max_wait
        last_state = None
        while time.time() < deadline:
            resp = self.session.get(url, params={"filter": "general"}, timeout=self.timeout)
            if resp.status_code == 404:
                time.sleep(interval)
                continue
            if resp.status_code == 429:
                wait = self._retry_after(resp) or interval
                time.sleep(wait)
                continue
            if resp.status_code >= 400:
                raise FilescanError(
                    f"filescan report failed: HTTP {resp.status_code} {resp.text[:200]}"
                )
            data = resp.json()
            reports = data.get("reports") or {}
            if isinstance(reports, dict) and reports:
                first = next(iter(reports.values()))
                state = first.get("state")
                last_state = state
                if state == "success":
                    return data
                if state in {"failure", "error"}:
                    raise FilescanError(f"filescan analysis state={state}")
            time.sleep(interval)
        raise FilescanError(
            f"filescan report timed out for {flow_id} after {max_wait}s (last state={last_state})"
        )

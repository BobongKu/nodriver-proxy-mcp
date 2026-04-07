"""Scope manager — controls which domains/URLs are recorded by the proxy.

Scope is persisted to ~/.nodriver-proxy-mcp/scope.json so that the mitmdump
addon (separate process) can read the same scope configuration.
"""

import json
from pathlib import Path
from urllib.parse import urlparse

SCOPE_FILE = Path.home() / ".nodriver-proxy-mcp" / "scope.json"

DEFAULT_IGNORE_EXTENSIONS = frozenset([
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".ts", ".m3u8",
    ".pdf", ".zip", ".gz",
])

DEFAULT_IGNORE_METHODS = frozenset(["OPTIONS"])


class ScopeManager:
    """Decides whether a request URL is in scope for recording.
    Reads from disk on every check so mitmdump addon stays in sync."""

    def __init__(self):
        self.ignore_extensions: frozenset[str] = DEFAULT_IGNORE_EXTENSIONS
        self.ignore_methods: frozenset[str] = DEFAULT_IGNORE_METHODS

    def set_domains(self, domains: list[str]):
        """Write allowed domains to disk."""
        SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {"allowed_domains": [d.lower().strip() for d in domains]}
        SCOPE_FILE.write_text(json.dumps(data), encoding="utf-8")

    def _get_domains(self) -> list[str]:
        """Read allowed domains from disk (shared with mitmdump addon)."""
        try:
            if SCOPE_FILE.exists():
                data = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
                return data.get("allowed_domains", [])
        except Exception:
            pass
        return []

    def is_allowed(self, url: str, method: str = "GET") -> bool:
        if method.upper() in self.ignore_methods:
            return False

        parsed = urlparse(url)
        path = parsed.path.lower()

        if any(path.endswith(ext) for ext in self.ignore_extensions):
            return False

        allowed = self._get_domains()
        if not allowed:
            return True

        host = parsed.hostname or ""
        return any(
            host == d or host.endswith(f".{d}")
            for d in allowed
        )

    def to_dict(self) -> dict:
        return {
            "allowed_domains": self._get_domains(),
            "ignore_extensions": sorted(self.ignore_extensions),
            "ignore_methods": sorted(self.ignore_methods),
        }


# Global instance
scope_manager = ScopeManager()

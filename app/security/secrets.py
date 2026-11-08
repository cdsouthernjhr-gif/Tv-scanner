"""API key storage — never in plain text.

Keys live in the OS credential store via ``keyring`` (Windows Credential
Manager on Windows). If no secure backend is available, keys are kept in
memory for the current session only and the caller is told so; nothing is
ever written to settings.json or the database.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)
SERVICE = "TVIntelligenceScanner"
KNOWN_KEYS = {
    "github_token": "GitHub personal access token (optional; raises rate limits, enables code search)",
    "gitlab_token": "GitLab personal access token (optional)",
    "google_cse_key": "Google Programmable Search JSON API key",
    "brave_search_key": "Brave Search API key",
}


class SecretStore:
    def __init__(self, backend=None):
        self._memory: dict[str, str] = {}
        self._kr = None
        try:
            import keyring
            from keyring.backends import fail
            kr = backend or keyring.get_keyring()
            if not isinstance(kr, fail.Keyring) and getattr(kr, "priority", 1) > 0:
                self._kr = kr
        except Exception as exc:   # keyring missing or broken
            log.warning("keyring unavailable: %s", exc)

    @property
    def secure(self) -> bool:
        """True when keys persist in an OS credential store."""
        return self._kr is not None

    @property
    def backend_name(self) -> str:
        return type(self._kr).__module__ + "." + type(self._kr).__name__ if self._kr else "session memory only"

    def set(self, name: str, value: str | None) -> str:
        """Store (or delete when value is empty). Returns where it was stored."""
        value = (value or "").strip()
        if self._kr:
            if value:
                self._kr.set_password(SERVICE, name, value)
            else:
                try:
                    self._kr.delete_password(SERVICE, name)
                except Exception:
                    pass
            return "credential store"
        if value:
            self._memory[name] = value
        else:
            self._memory.pop(name, None)
        return "session memory (not persisted — no secure credential store available)"

    def get(self, name: str) -> str | None:
        if self._kr:
            try:
                return self._kr.get_password(SERVICE, name)
            except Exception as exc:
                log.warning("keyring read failed: %s", exc)
                return None
        return self._memory.get(name)

    def has(self, name: str) -> bool:
        return bool(self.get(name))

    @staticmethod
    def mask(value: str | None) -> str:
        if not value:
            return "not set"
        return value[:4] + "…" + value[-2:] if len(value) > 8 else "set"

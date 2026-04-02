"""In-memory session store for the sncro relay."""

import asyncio
import time
from collections import deque


class SessionStore:
    """Keyed storage with snapshots, request queues, and response slots."""

    def __init__(self, expiry_hours: int = 4):
        self.expiry_seconds = expiry_hours * 3600
        self._sessions: dict[str, dict] = {}

    def _new_session(self, secret: str = "") -> dict:
        return {
            "created_at": time.time(),
            "last_seen": time.time(),
            "secret": secret,
            "snapshot": None,
            "requests": deque(),
            "responses": {},
        }

    def ensure_session(self, key: str, secret: str = "") -> None:
        if key not in self._sessions:
            self._sessions[key] = self._new_session(secret=secret)
        self._sessions[key]["last_seen"] = time.time()

    def verify_secret(self, key: str, secret: str) -> bool:
        """Check if the secret matches. Returns True if no secret was set (legacy)."""
        if key not in self._sessions:
            return False
        stored = self._sessions[key].get("secret", "")
        if not stored:
            return True  # No secret set — legacy session, allow access
        return stored == secret

    def has_session(self, key: str) -> bool:
        return key in self._sessions

    # --- Snapshot ---

    def set_snapshot(self, key: str, data: dict) -> None:
        self._sessions[key]["snapshot"] = data

    def get_snapshot(self, key: str) -> dict | None:
        return self._sessions[key]["snapshot"]

    # --- Requests (MCP → browser) ---

    def add_request(self, key: str, request: dict) -> None:
        self._sessions[key]["requests"].append(request)

    def pop_request(self, key: str) -> dict | None:
        q = self._sessions[key]["requests"]
        return q.popleft() if q else None

    # --- Responses (browser → MCP) ---

    def add_response(self, key: str, request_id: str, response: dict) -> None:
        self._sessions[key]["responses"][request_id] = response

    def pop_response(self, key: str, request_id: str) -> dict | None:
        return self._sessions[key]["responses"].pop(request_id, None)

    # --- Cleanup ---

    async def cleanup_loop(self, interval: int = 300) -> None:
        """Periodically remove expired sessions."""
        while True:
            await asyncio.sleep(interval)
            now = time.time()
            expired = [
                k for k, v in self._sessions.items()
                if now - v["last_seen"] > self.expiry_seconds
            ]
            for k in expired:
                del self._sessions[k]

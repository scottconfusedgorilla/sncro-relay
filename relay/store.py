"""In-memory session store for the sncro relay."""

import asyncio
import secrets
import time
from collections import deque


class SessionStore:
    """Keyed storage with snapshots, request queues, and response slots."""

    def __init__(self, expiry_minutes: int = 30):
        self.expiry_seconds = expiry_minutes * 60
        self._sessions: dict[str, dict] = {}

    def _new_session(self, secret: str = "", browser_secret: str = "", db_id: str = "") -> dict:
        return {
            "created_at": time.time(),
            "last_seen": time.time(),
            "secret": secret,
            "browser_secret": browser_secret,
            "db_id": db_id,
            "snapshot": None,
            "connected": False,
            "consumed": False,
            "tools_used": set(),
            "requests": deque(),
            "responses": {},
        }

    def ensure_session(self, key: str, secret: str = "", browser_secret: str = "", db_id: str = "") -> None:
        if key not in self._sessions:
            self._sessions[key] = self._new_session(secret=secret, browser_secret=browser_secret, db_id=db_id)
        self._sessions[key]["last_seen"] = time.time()

    def touch(self, key: str) -> bool:
        """Update last_seen without creating a new session. Returns False if key unknown."""
        if key not in self._sessions:
            return False
        self._sessions[key]["last_seen"] = time.time()
        return True

    def get_browser_secret(self, key: str) -> str:
        return self._sessions.get(key, {}).get("browser_secret", "")

    def get_db_id(self, key: str) -> str:
        return self._sessions.get(key, {}).get("db_id", "")

    def record_tool(self, key: str, tool_name: str) -> None:
        if key in self._sessions:
            self._sessions[key]["tools_used"].add(tool_name)

    def get_tools_used(self, key: str) -> list[str]:
        if key in self._sessions:
            return list(self._sessions[key]["tools_used"])
        return []

    def mark_connected(self, key: str) -> bool:
        """Mark session as connected. Returns True if this is the first connection."""
        if key in self._sessions and not self._sessions[key]["connected"]:
            self._sessions[key]["connected"] = True
            return True
        return False

    def consume(self, key: str) -> bool:
        """Mark session as consumed (bound to a browser). Returns False if already consumed."""
        if key in self._sessions:
            if self._sessions[key]["consumed"]:
                return False
            self._sessions[key]["consumed"] = True
            return True
        return False

    def is_consumed(self, key: str) -> bool:
        return self._sessions.get(key, {}).get("consumed", False)

    def is_connected(self, key: str) -> bool:
        """Check if the browser has sent at least one snapshot."""
        return self._sessions.get(key, {}).get("connected", False)

    def get_session_info(self, key: str) -> dict | None:
        """Return basic session metadata (created_at, connected, consumed)."""
        s = self._sessions.get(key)
        if not s:
            return None
        return {
            "created_at": s["created_at"],
            "connected": s["connected"],
            "consumed": s["consumed"],
        }

    def verify_secret(self, key: str, secret: str) -> bool:
        """Constant-time secret check. Returns False if no secret was stored."""
        if key not in self._sessions:
            return False
        stored = self._sessions[key].get("secret", "")
        if not stored or not secret:
            return False
        return secrets.compare_digest(stored, secret)

    def verify_browser_secret(self, key: str, browser_secret: str) -> bool:
        """Constant-time check of the browser-side secret (set at /enable)."""
        if key not in self._sessions:
            return False
        stored = self._sessions[key].get("browser_secret", "")
        if not stored or not browser_secret:
            return False
        return secrets.compare_digest(stored, browser_secret)

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

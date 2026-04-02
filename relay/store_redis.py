"""Redis-backed session store for horizontal scaling.

Drop-in replacement for store.py. Same interface, backed by Redis
instead of an in-memory dict. Enables multiple relay workers behind
a load balancer — any instance can handle any session.

Usage:
    from relay.store_redis import RedisSessionStore
    store = RedisSessionStore(redis_url="redis://...", expiry_hours=4)

Key schema:
    sncro:{key}:snapshot     — hash (latest baseline snapshot)
    sncro:{key}:requests     — list (pending requests, FIFO)
    sncro:{key}:resp:{rid}   — string (response for a specific request_id)

All keys expire after expiry_hours — no cleanup loop needed.
"""

import json
import redis


class RedisSessionStore:

    def __init__(self, redis_url: str, expiry_hours: int = 4):
        self.r = redis.from_url(redis_url, decode_responses=True)
        self.ttl = expiry_hours * 3600

    def _touch(self, key: str):
        """Refresh TTL on all keys for this session."""
        for suffix in ("snapshot", "requests"):
            self.r.expire(f"sncro:{key}:{suffix}", self.ttl)

    def ensure_session(self, key: str) -> None:
        # Just touch — Redis keys are created on first write
        self._touch(key)

    def has_session(self, key: str) -> bool:
        return self.r.exists(f"sncro:{key}:snapshot") > 0

    # --- Snapshot ---

    def set_snapshot(self, key: str, data: dict) -> None:
        self.r.set(f"sncro:{key}:snapshot", json.dumps(data), ex=self.ttl)

    def get_snapshot(self, key: str) -> dict | None:
        raw = self.r.get(f"sncro:{key}:snapshot")
        return json.loads(raw) if raw else None

    # --- Requests (MCP → browser) ---

    def add_request(self, key: str, request: dict) -> None:
        self.r.rpush(f"sncro:{key}:requests", json.dumps(request))
        self.r.expire(f"sncro:{key}:requests", self.ttl)

    def pop_request(self, key: str) -> dict | None:
        raw = self.r.lpop(f"sncro:{key}:requests")
        return json.loads(raw) if raw else None

    # --- Responses (browser → MCP) ---

    def add_response(self, key: str, request_id: str, response: dict) -> None:
        self.r.set(f"sncro:{key}:resp:{request_id}", json.dumps(response), ex=300)

    def pop_response(self, key: str, request_id: str) -> dict | None:
        rkey = f"sncro:{key}:resp:{request_id}"
        raw = self.r.get(rkey)
        if raw:
            self.r.delete(rkey)
            return json.loads(raw)
        return None

    # No cleanup_loop needed — Redis TTL handles expiry
    async def cleanup_loop(self, interval: int = 300) -> None:
        """No-op. Redis TTL handles expiry automatically."""
        import asyncio
        while True:
            await asyncio.sleep(interval)

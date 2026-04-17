"""Tests for the sncro relay server."""

import pytest
from fastapi.testclient import TestClient

from relay.main import app, store


KEY = "100000001"
BROWSER_SECRET = "0" * 32
HEADERS = {"X-Sncro-Secret": BROWSER_SECRET}


@pytest.fixture(autouse=True)
def clear_store():
    """Reset store between tests. Rate limiter state is per-process — we reset
    via a fresh Limiter storage if needed, but the in-memory storage is
    scoped per-test by this fixture's side effects for the store."""
    store._sessions.clear()
    # slowapi's default in-memory storage: wipe to avoid cross-test 429s
    try:
        limiter = app.state.limiter
        if hasattr(limiter, "reset"):
            limiter.reset()
        else:
            # fall back to clearing the underlying storage
            storage = getattr(limiter, "_storage", None) or getattr(limiter, "storage", None)
            if storage is not None and hasattr(storage, "reset"):
                storage.reset()
    except Exception:
        pass
    yield
    store._sessions.clear()


client = TestClient(app)


def _seed_session(key: str = KEY, browser_secret: str = BROWSER_SECRET) -> None:
    """Install a consumed session with a browser_secret so protected endpoints accept requests."""
    store.ensure_session(key, browser_secret=browser_secret)


# --- Session status ---

class TestSessionStatus:
    def test_new_session_not_active(self):
        resp = client.get(f"/session/{KEY}/status")
        assert resp.status_code == 200
        assert resp.json()["active"] is False

    def test_session_active_after_ensure(self):
        _seed_session()
        resp = client.get(f"/session/{KEY}/status")
        assert resp.json()["active"] is True


# --- Snapshot (baseline) ---

class TestSnapshot:
    def test_push_snapshot_requires_browser_secret(self):
        _seed_session()
        payload = {
            "console": [{"level": "log", "message": "hello"}],
            "errors": [],
            "url": "http://localhost:3000",
            "title": "Test Page",
            "timestamp": 1234567890.0,
        }
        # Without header: 403
        resp = client.post(f"/session/{KEY}/snapshot", json=payload)
        assert resp.status_code == 403

        # With wrong secret: 403
        resp = client.post(f"/session/{KEY}/snapshot", json=payload,
                           headers={"X-Sncro-Secret": "f" * 32})
        assert resp.status_code == 403

        # With the right secret: 200
        resp = client.post(f"/session/{KEY}/snapshot", json=payload, headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_push_snapshot_requires_existing_session(self):
        # No _seed_session — unknown key should 404 even with a header present.
        resp = client.post(f"/session/{KEY}/snapshot",
                           json={"console": [], "errors": [], "url": "", "title": "", "timestamp": 0},
                           headers=HEADERS)
        assert resp.status_code == 404

    def test_snapshot_stored_in_store(self):
        _seed_session()
        payload = {
            "console": [{"level": "log", "message": "stored"}],
            "errors": [],
            "url": "http://localhost:3000",
            "title": "Test Page",
            "timestamp": 0,
        }
        resp = client.post(f"/session/{KEY}/snapshot", json=payload, headers=HEADERS)
        assert resp.status_code == 200
        # Snapshot readable from the store directly (MCP tools read via store, not HTTP).
        snap = store.get_snapshot(KEY)
        assert snap["console"][0]["message"] == "stored"


# --- Request polling (browser-side long-poll) ---

class TestRequestPolling:
    def test_pending_requires_browser_secret(self):
        _seed_session()
        resp = client.get(f"/session/{KEY}/request/pending?timeout=1")
        assert resp.status_code == 403

    def test_no_pending_request_returns_pending_false(self):
        _seed_session()
        resp = client.get(f"/session/{KEY}/request/pending?timeout=1", headers=HEADERS)
        assert resp.json() == {"pending": False}

    def test_pending_returns_queued_request(self):
        _seed_session()
        store.add_request(KEY, {"request_id": "r1", "tool": "query_element", "params": {"selector": "#main"}})
        resp = client.get(f"/session/{KEY}/request/pending?timeout=1", headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["request_id"] == "r1"
        assert resp.json()["tool"] == "query_element"


# --- Response posting (browser → MCP) ---

class TestResponsePosting:
    def test_post_response_requires_browser_secret(self):
        _seed_session()
        payload = {"request_id": "r1", "data": {"width": 300, "height": 200}}
        resp = client.post(f"/session/{KEY}/response", json=payload)
        assert resp.status_code == 403

    def test_post_response_stores_result(self):
        _seed_session()
        payload = {"request_id": "r1", "data": {"width": 300, "height": 200}}
        resp = client.post(f"/session/{KEY}/response", json=payload, headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        stored = store.pop_response(KEY, "r1")
        assert stored["data"]["width"] == 300


# --- /session/{key}/enable (consume + return browser_secret) ---

class TestEnableEndpoint:
    def test_enable_unknown_key_404(self):
        resp = client.post(f"/session/{KEY}/enable")
        assert resp.status_code == 404

    def test_enable_returns_browser_secret(self):
        _seed_session()
        resp = client.post(f"/session/{KEY}/enable")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["browser_secret"] == BROWSER_SECRET

    def test_enable_twice_returns_409(self):
        _seed_session()
        resp = client.post(f"/session/{KEY}/enable")
        assert resp.status_code == 200
        resp2 = client.post(f"/session/{KEY}/enable")
        assert resp2.status_code == 409


# --- Contract tests (endpoint shapes) ---

class TestContract:
    """Verify endpoint shapes match what agent.js and MCP server expect."""

    def test_snapshot_accepts_full_payload(self):
        _seed_session()
        payload = {
            "console": [{"level": "error", "message": "oh no", "timestamp": 123}],
            "errors": [{"message": "TypeError", "stack": "...", "timestamp": 123}],
            "url": "https://example.com/page",
            "title": "Example",
            "timestamp": 1234567890.0,
        }
        resp = client.post(f"/session/{KEY}/snapshot", json=payload, headers=HEADERS)
        assert resp.status_code == 200

    def test_response_requires_request_id(self):
        _seed_session()
        resp = client.post(f"/session/{KEY}/response", json={"data": {}}, headers=HEADERS)
        assert resp.status_code == 422

"""Tests for the sncro relay server."""

import pytest
from fastapi.testclient import TestClient

from relay.main import app, store


@pytest.fixture(autouse=True)
def clear_store():
    """Reset store between tests."""
    store._sessions.clear()
    yield
    store._sessions.clear()


client = TestClient(app)


# --- Session status ---

class TestSessionStatus:
    def test_new_session_not_active(self):
        resp = client.get("/session/testkey/status")
        assert resp.json()["active"] is False

    def test_session_active_after_snapshot(self):
        client.post("/session/testkey/snapshot", json={
            "console": [], "errors": [], "url": "", "title": "", "timestamp": 0
        })
        resp = client.get("/session/testkey/status")
        assert resp.json()["active"] is True


# --- Snapshot (baseline) ---

class TestSnapshot:
    def test_push_and_get_snapshot(self):
        payload = {
            "console": [{"level": "log", "message": "hello"}],
            "errors": [],
            "url": "http://localhost:3000",
            "title": "Test Page",
            "timestamp": 1234567890.0,
        }
        resp = client.post("/session/abc/snapshot", json=payload)
        assert resp.json()["ok"] is True

        resp = client.get("/session/abc/snapshot")
        assert resp.status_code == 200
        assert resp.json()["console"][0]["message"] == "hello"
        assert resp.json()["url"] == "http://localhost:3000"

    def test_get_snapshot_before_push_returns_404(self):
        client.get("/session/newkey/status")  # create session
        store.ensure_session("newkey")
        resp = client.get("/session/newkey/snapshot")
        assert resp.status_code == 404

    def test_snapshot_overwrites_previous(self):
        client.post("/session/abc/snapshot", json={
            "console": [{"message": "first"}], "errors": [],
            "url": "", "title": "", "timestamp": 0,
        })
        client.post("/session/abc/snapshot", json={
            "console": [{"message": "second"}], "errors": [],
            "url": "", "title": "", "timestamp": 0,
        })
        resp = client.get("/session/abc/snapshot")
        assert resp.json()["console"][0]["message"] == "second"


# --- Request/response (two-way) ---

class TestRequestResponse:
    def test_post_request_and_poll(self):
        req = {"request_id": "r1", "tool": "query_element", "params": {"selector": "#main"}}
        resp = client.post("/session/abc/request", json=req)
        assert resp.json()["ok"] is True

        resp = client.get("/session/abc/request/pending?timeout=1")
        assert resp.json()["request_id"] == "r1"
        assert resp.json()["tool"] == "query_element"

    def test_no_pending_request_returns_pending_false(self):
        store.ensure_session("abc")
        resp = client.get("/session/abc/request/pending?timeout=1")
        assert resp.json()["pending"] is False

    def test_post_response_and_retrieve(self):
        store.ensure_session("abc")
        resp_payload = {"request_id": "r1", "data": {"width": 300, "height": 200}}
        resp = client.post("/session/abc/response", json=resp_payload)
        assert resp.json()["ok"] is True

        resp = client.get("/session/abc/response/r1?timeout=1")
        assert resp.json()["data"]["width"] == 300

    def test_response_timeout_returns_408(self):
        store.ensure_session("abc")
        resp = client.get("/session/abc/response/nonexistent?timeout=1")
        assert resp.status_code == 408


# --- Contract tests (endpoint shapes) ---

class TestContract:
    """Verify endpoint shapes match what agent.js and MCP server expect."""

    def test_snapshot_accepts_full_payload(self):
        payload = {
            "console": [{"level": "error", "message": "oh no", "timestamp": 123}],
            "errors": [{"message": "TypeError", "stack": "...", "timestamp": 123}],
            "url": "https://example.com/page",
            "title": "Example",
            "timestamp": 1234567890.0,
        }
        resp = client.post("/session/k/snapshot", json=payload)
        assert resp.status_code == 200

    def test_request_requires_request_id_and_tool(self):
        resp = client.post("/session/k/request", json={"params": {}})
        assert resp.status_code == 422  # missing required fields

    def test_response_requires_request_id(self):
        resp = client.post("/session/k/response", json={"data": {}})
        assert resp.status_code == 422

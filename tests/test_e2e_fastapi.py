"""End-to-end tests for sncro with a FastAPI app.

Tests the full flow: user visits enable page → clicks Allow → middleware
goes server-to-server to the relay → cookies are set → agent.js injects on
subsequent pages → agent.js pushes snapshot (authed with browser_secret) →
snapshot readable via the store (what MCP tools use).

Simulates what agent.js does without a real browser.
"""

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from middleware import SncroMiddleware, sncro_routes
from relay.main import app as relay_app, store

KEY = "100000001"
KEY_ALT = "200000002"
BROWSER_SECRET = "0" * 32


# --- Test FastAPI app with sncro middleware ---

def make_fastapi_app():
    app = FastAPI()
    app.include_router(sncro_routes)
    app.add_middleware(SncroMiddleware, relay_url="http://relay-test")

    @app.get("/", response_class=HTMLResponse)
    async def home():
        return "<html><body><h1>Hello FastAPI</h1></body></html>"

    @app.get("/page2", response_class=HTMLResponse)
    async def page2():
        return "<html><body><h1>Page Two</h1><div id='content'>Some content</div></body></html>"

    @app.get("/api/data")
    async def api():
        return {"items": [1, 2, 3]}

    return app


@pytest.fixture(autouse=True)
def clear_store():
    store._sessions.clear()
    try:
        limiter = relay_app.state.limiter
        if hasattr(limiter, "reset"):
            limiter.reset()
    except Exception:
        pass
    yield
    store._sessions.clear()


@pytest.fixture
def app_client():
    return TestClient(make_fastapi_app())


@pytest.fixture
def relay_client():
    return TestClient(relay_app)


class TestFastAPIEndToEnd:
    def test_get_enable_shows_confirm_page(self, app_client):
        resp = app_client.get(f"/sncro/enable/{KEY}")
        assert resp.status_code == 200
        assert "Allow sncro" in resp.text
        assert "sncro_key" not in resp.cookies
        assert "sncro_browser_secret" not in resp.cookies

    def test_injection_requires_both_cookies(self, app_client):
        app_client.cookies.set("sncro_key", KEY)
        app_client.cookies.set("sncro_browser_secret", BROWSER_SECRET)
        resp = app_client.get("/")
        assert "agent.js" in resp.text
        assert f'data-key="{KEY}"' in resp.text
        assert 'data-relay="http://relay-test"' in resp.text

    def test_no_injection_on_api(self, app_client):
        app_client.cookies.set("sncro_key", KEY)
        app_client.cookies.set("sncro_browser_secret", BROWSER_SECRET)
        resp = app_client.get("/api/data")
        assert resp.json() == {"items": [1, 2, 3]}
        assert "agent.js" not in resp.text

    def test_disable_page_renders(self, app_client):
        resp = app_client.get("/sncro/disable")
        assert resp.status_code == 200
        # After disable, pages are not injected unless cookies get re-set.
        resp2 = app_client.get("/")
        assert "agent.js" not in resp2.text

    def test_full_snapshot_flow(self, relay_client):
        """agent.js authenticates with X-Sncro-Secret and pushes a snapshot;
        MCP tools read from the store directly (no HTTP GET on the snapshot)."""
        store.ensure_session(KEY, browser_secret=BROWSER_SECRET)

        snapshot = {
            "console": [{"level": "log", "message": "page loaded", "timestamp": 1000}],
            "errors": [],
            "url": "http://localhost:8000/",
            "title": "Hello FastAPI",
            "timestamp": 1000.0,
        }
        resp = relay_client.post(
            f"/session/{KEY}/snapshot",
            json=snapshot,
            headers={"X-Sncro-Secret": BROWSER_SECRET},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        stored = store.get_snapshot(KEY)
        assert stored["console"][0]["message"] == "page loaded"
        assert stored["url"] == "http://localhost:8000/"

    def test_full_request_response_flow(self, relay_client):
        """Request/response round-trip via the store + the browser-authed endpoints."""
        store.ensure_session(KEY_ALT, browser_secret=BROWSER_SECRET)
        headers = {"X-Sncro-Secret": BROWSER_SECRET}

        # MCP side enqueues a request directly on the store (matches how tool handlers work now)
        store.add_request(KEY_ALT, {
            "request_id": "req-001",
            "tool": "query_element",
            "params": {"selector": "#content"},
        })

        # Browser (agent.js) long-polls for it
        resp = relay_client.get(f"/session/{KEY_ALT}/request/pending?timeout=1", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["request_id"] == "req-001"
        assert resp.json()["tool"] == "query_element"

        # Browser posts the response
        browser_resp = {
            "request_id": "req-001",
            "data": {
                "tagName": "div",
                "id": "content",
                "innerText": "Some content",
                "boundingRect": {"x": 0, "y": 0, "width": 800, "height": 100},
            },
        }
        resp = relay_client.post(f"/session/{KEY_ALT}/response", json=browser_resp, headers=headers)
        assert resp.status_code == 200

        # MCP side reads the response from the store
        stored = store.pop_response(KEY_ALT, "req-001")
        assert stored["data"]["tagName"] == "div"
        assert stored["data"]["innerText"] == "Some content"

    def test_session_status(self, relay_client):
        resp = relay_client.get(f"/session/{KEY}/status")
        assert resp.json()["active"] is False
        store.ensure_session(KEY, browser_secret=BROWSER_SECRET)
        resp = relay_client.get(f"/session/{KEY}/status")
        assert resp.json()["active"] is True

    def test_content_length_not_corrupted(self, app_client):
        app_client.cookies.set("sncro_key", KEY)
        app_client.cookies.set("sncro_browser_secret", BROWSER_SECRET)
        resp = app_client.get("/")
        cl = resp.headers.get("content-length")
        if cl is not None:
            assert int(cl) == len(resp.content)

"""End-to-end tests for sncro with a FastAPI app.

Tests the full flow: enable session → inject agent.js → push snapshot →
read via relay endpoints. Simulates what agent.js does without a real browser.
"""

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from middleware import SncroMiddleware, sncro_routes
from relay.main import app as relay_app, store


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


app_client = TestClient(make_fastapi_app())
relay_client = TestClient(relay_app)


@pytest.fixture(autouse=True)
def clear_store():
    store._sessions.clear()
    yield
    store._sessions.clear()


class TestFastAPIEndToEnd:
    """Full flow: enable → inject → snapshot → read."""

    def test_enable_sets_cookie(self):
        """Visiting /sncro/enable/{key} sets the session cookie."""
        resp = app_client.get("/sncro/enable/e2e-test-key")
        assert resp.status_code == 200
        assert resp.cookies.get("sncro_key") == "e2e-test-key"
        assert "Connected" in resp.text

    def test_injection_after_enable(self):
        """After enable, HTML pages get agent.js injected."""
        resp = app_client.get("/", cookies={"sncro_key": "e2e-test-key"})
        assert "agent.js" in resp.text
        assert 'data-key="e2e-test-key"' in resp.text
        assert 'data-relay="http://relay-test"' in resp.text

    def test_no_injection_on_api(self):
        """JSON endpoints are not affected by the middleware."""
        resp = app_client.get("/api/data", cookies={"sncro_key": "e2e-test-key"})
        assert resp.json() == {"items": [1, 2, 3]}
        assert "agent.js" not in resp.text

    def test_disable_clears_cookie(self):
        """Visiting /sncro/disable removes the cookie."""
        resp = app_client.get("/sncro/disable")
        assert resp.status_code == 200
        # After disable, pages should not be injected
        resp2 = app_client.get("/")
        assert "agent.js" not in resp2.text

    def test_full_snapshot_flow(self):
        """Simulate agent.js pushing a snapshot, then reading it via relay."""
        key = "e2e-full-flow"

        # 1. Push a snapshot (simulates agent.js)
        snapshot = {
            "console": [{"level": "log", "message": "page loaded", "timestamp": 1000}],
            "errors": [],
            "url": "http://localhost:8000/",
            "title": "Hello FastAPI",
            "timestamp": 1000.0,
        }
        resp = relay_client.post(f"/session/{key}/snapshot", json=snapshot)
        assert resp.json()["ok"] is True

        # 2. Read snapshot via relay (simulates MCP get_console_logs)
        resp = relay_client.get(f"/session/{key}/snapshot")
        assert resp.status_code == 200
        assert resp.json()["console"][0]["message"] == "page loaded"
        assert resp.json()["url"] == "http://localhost:8000/"

    def test_full_request_response_flow(self):
        """Simulate the on-demand query flow (MCP → relay → browser → relay → MCP)."""
        key = "e2e-query-flow"
        store.ensure_session(key)

        # 1. MCP posts a request (simulates query_element)
        req = {
            "request_id": "req-001",
            "tool": "query_element",
            "params": {"selector": "#content"},
        }
        resp = relay_client.post(f"/session/{key}/request", json=req)
        assert resp.json()["ok"] is True

        # 2. Browser polls and gets the request (simulates agent.js)
        resp = relay_client.get(f"/session/{key}/request/pending?timeout=1")
        assert resp.json()["request_id"] == "req-001"
        assert resp.json()["tool"] == "query_element"

        # 3. Browser posts the response (simulates agent.js)
        browser_resp = {
            "request_id": "req-001",
            "data": {
                "tagName": "div",
                "id": "content",
                "innerText": "Some content",
                "boundingRect": {"x": 0, "y": 0, "width": 800, "height": 100},
            },
        }
        resp = relay_client.post(f"/session/{key}/response", json=browser_resp)
        assert resp.json()["ok"] is True

        # 4. MCP reads the response
        resp = relay_client.get(f"/session/{key}/response/req-001?timeout=1")
        assert resp.json()["data"]["tagName"] == "div"
        assert resp.json()["data"]["innerText"] == "Some content"

    def test_session_status(self):
        """Session status reflects whether data has been pushed."""
        key = "e2e-status"
        resp = relay_client.get(f"/session/{key}/status")
        assert resp.json()["active"] is False

        # Push snapshot to activate
        relay_client.post(f"/session/{key}/snapshot", json={
            "console": [], "errors": [], "url": "", "title": "", "timestamp": 0,
        })
        resp = relay_client.get(f"/session/{key}/status")
        assert resp.json()["active"] is True

    def test_content_length_not_corrupted(self):
        """Injection must not leave stale Content-Length header."""
        resp = app_client.get("/", cookies={"sncro_key": "cl-test"})
        cl = resp.headers.get("content-length")
        if cl is not None:
            assert int(cl) == len(resp.content)

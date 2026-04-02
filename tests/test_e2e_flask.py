"""End-to-end tests for sncro with a Flask app.

Tests the full flow: enable session → inject agent.js → push snapshot →
read via relay endpoints. Simulates what agent.js does without a real browser.
"""

import pytest
from flask import Flask
from fastapi.testclient import TestClient as RelayClient

from middleware.sncro_flask import init_sncro
from relay.main import app as relay_app, store


# --- Test Flask app with sncro middleware ---

def make_flask_app():
    app = Flask(__name__)

    @app.route("/")
    def home():
        return "<html><body><h1>Hello Flask</h1></body></html>"

    @app.route("/page2")
    def page2():
        return "<html><body><h1>Page Two</h1><div id='content'>Some content</div></body></html>"

    @app.route("/api/data")
    def api():
        import json
        return app.response_class(json.dumps({"items": [1, 2, 3]}), mimetype="application/json")

    init_sncro(app, relay_url="http://relay-test")
    return app


flask_app = make_flask_app()
flask_client = flask_app.test_client()
relay_client = RelayClient(relay_app)


@pytest.fixture(autouse=True)
def clear_store():
    store._sessions.clear()
    yield
    store._sessions.clear()


class TestFlaskEndToEnd:
    """Full flow: enable → inject → snapshot → read."""

    def test_enable_sets_cookie(self):
        """Visiting /sncro/enable/{key} sets the session cookie."""
        resp = flask_client.get("/sncro/enable/e2e-flask-key")
        assert resp.status_code == 200
        # Flask test client stores cookies internally; verify by making another request
        resp2 = flask_client.get("/")
        assert b"agent.js" in resp2.data
        assert b'data-key="e2e-flask-key"' in resp2.data
        assert b"Connected" in resp.data

    def test_injection_after_enable(self):
        """After enable, HTML pages get agent.js injected."""
        # Set cookie first
        flask_client.get("/sncro/enable/e2e-flask-key")
        resp = flask_client.get("/")
        assert b"agent.js" in resp.data
        assert b'data-key="e2e-flask-key"' in resp.data
        assert b'data-relay="http://relay-test"' in resp.data

    def test_no_injection_on_json(self):
        """JSON endpoints are not affected."""
        flask_client.get("/sncro/enable/e2e-flask-key")
        resp = flask_client.get("/api/data")
        assert resp.json == {"items": [1, 2, 3]}
        assert b"agent.js" not in resp.data

    def test_disable_clears_cookie(self):
        """Visiting /sncro/disable removes the cookie."""
        flask_client.get("/sncro/enable/e2e-flask-key")
        resp = flask_client.get("/sncro/disable")
        assert resp.status_code == 200
        # Get a fresh client to verify cookie is gone
        resp2 = flask_client.get("/")
        # After disable, the cookie should be cleared
        assert b"agent.js" not in resp2.data

    def test_full_snapshot_flow(self):
        """Simulate agent.js pushing a snapshot, then reading it via relay."""
        key = "e2e-flask-snapshot"

        snapshot = {
            "console": [{"level": "log", "message": "flask loaded", "timestamp": 2000}],
            "errors": [],
            "url": "http://localhost:5000/",
            "title": "Hello Flask",
            "timestamp": 2000.0,
        }
        resp = relay_client.post(f"/session/{key}/snapshot", json=snapshot)
        assert resp.json()["ok"] is True

        resp = relay_client.get(f"/session/{key}/snapshot")
        assert resp.status_code == 200
        assert resp.json()["console"][0]["message"] == "flask loaded"

    def test_full_request_response_flow(self):
        """Simulate the on-demand query flow."""
        key = "e2e-flask-query"
        store.ensure_session(key)

        req = {
            "request_id": "freq-001",
            "tool": "get_page_snapshot",
            "params": {},
        }
        resp = relay_client.post(f"/session/{key}/request", json=req)
        assert resp.json()["ok"] is True

        resp = relay_client.get(f"/session/{key}/request/pending?timeout=1")
        assert resp.json()["request_id"] == "freq-001"

        browser_resp = {
            "request_id": "freq-001",
            "data": {
                "url": "http://localhost:5000/",
                "title": "Hello Flask",
                "viewport": {"width": 1024, "height": 768},
            },
        }
        resp = relay_client.post(f"/session/{key}/response", json=browser_resp)
        assert resp.json()["ok"] is True

        resp = relay_client.get(f"/session/{key}/response/freq-001?timeout=1")
        assert resp.json()["data"]["title"] == "Hello Flask"

    def test_content_length_not_corrupted(self):
        """Injection must not leave stale Content-Length."""
        flask_client.get("/sncro/enable/cl-flask-test")
        resp = flask_client.get("/")
        cl = resp.headers.get("Content-Length")
        if cl is not None:
            assert int(cl) == len(resp.data)

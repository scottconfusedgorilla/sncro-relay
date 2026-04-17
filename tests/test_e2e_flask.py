"""End-to-end tests for sncro with a Flask app.

Mirrors test_e2e_fastapi.py but against the Flask middleware.
"""

import pytest
from flask import Flask
from fastapi.testclient import TestClient as RelayClient

from middleware.sncro_flask import init_sncro
from relay.main import app as relay_app, store

KEY = "100000001"
KEY_ALT = "200000002"
BROWSER_SECRET = "0" * 32


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
def flask_client():
    return make_flask_app().test_client()


@pytest.fixture
def relay_client():
    return RelayClient(relay_app)


class TestFlaskEndToEnd:
    def test_get_enable_shows_confirm_page(self, flask_client):
        resp = flask_client.get(f"/sncro/enable/{KEY}")
        assert resp.status_code == 200
        assert b"Allow sncro" in resp.data
        # GET must not set cookies — only POST /confirm does (with Origin check).
        cookies = resp.headers.getlist("Set-Cookie")
        assert not any("sncro_key" in c for c in cookies)

    def test_injection_requires_both_cookies(self, flask_client):
        flask_client.set_cookie("sncro_key", KEY, domain="localhost")
        flask_client.set_cookie("sncro_browser_secret", BROWSER_SECRET, domain="localhost")
        resp = flask_client.get("/")
        assert b"agent.js" in resp.data
        assert f'data-key="{KEY}"'.encode() in resp.data
        assert b'data-relay="http://relay-test"' in resp.data

    def test_no_injection_on_json(self, flask_client):
        flask_client.set_cookie("sncro_key", KEY, domain="localhost")
        flask_client.set_cookie("sncro_browser_secret", BROWSER_SECRET, domain="localhost")
        resp = flask_client.get("/api/data")
        assert resp.json == {"items": [1, 2, 3]}
        assert b"agent.js" not in resp.data

    def test_disable_page_renders(self, flask_client):
        resp = flask_client.get("/sncro/disable")
        assert resp.status_code == 200
        assert b"sncro disabled" in resp.data.lower()

    def test_full_snapshot_flow(self, relay_client):
        store.ensure_session(KEY, browser_secret=BROWSER_SECRET)
        snapshot = {
            "console": [{"level": "log", "message": "flask loaded", "timestamp": 2000}],
            "errors": [],
            "url": "http://localhost:5000/",
            "title": "Hello Flask",
            "timestamp": 2000.0,
        }
        resp = relay_client.post(
            f"/session/{KEY}/snapshot",
            json=snapshot,
            headers={"X-Sncro-Secret": BROWSER_SECRET},
        )
        assert resp.status_code == 200
        stored = store.get_snapshot(KEY)
        assert stored["console"][0]["message"] == "flask loaded"

    def test_full_request_response_flow(self, relay_client):
        store.ensure_session(KEY_ALT, browser_secret=BROWSER_SECRET)
        headers = {"X-Sncro-Secret": BROWSER_SECRET}
        store.add_request(KEY_ALT, {
            "request_id": "freq-001",
            "tool": "get_page_snapshot",
            "params": {},
        })

        resp = relay_client.get(f"/session/{KEY_ALT}/request/pending?timeout=1", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["request_id"] == "freq-001"

        browser_resp = {
            "request_id": "freq-001",
            "data": {
                "url": "http://localhost:5000/",
                "title": "Hello Flask",
                "viewport": {"width": 1024, "height": 768},
            },
        }
        resp = relay_client.post(f"/session/{KEY_ALT}/response", json=browser_resp, headers=headers)
        assert resp.status_code == 200

        stored = store.pop_response(KEY_ALT, "freq-001")
        assert stored["data"]["title"] == "Hello Flask"

    def test_content_length_not_corrupted(self, flask_client):
        flask_client.set_cookie("sncro_key", KEY, domain="localhost")
        flask_client.set_cookie("sncro_browser_secret", BROWSER_SECRET, domain="localhost")
        resp = flask_client.get("/")
        cl = resp.headers.get("Content-Length")
        if cl is not None:
            assert int(cl) == len(resp.data)

"""Tests for the sncro FastAPI middleware."""

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from middleware import SncroMiddleware, sncro_routes


def make_app(relay_url="https://sncro.net"):
    app = FastAPI()
    app.include_router(sncro_routes)
    app.add_middleware(SncroMiddleware, relay_url=relay_url)

    @app.get("/", response_class=HTMLResponse)
    async def home():
        return "<html><body><h1>Hello</h1></body></html>"

    @app.get("/api/data")
    async def api():
        return {"data": 1}

    return app


client = TestClient(make_app())


class TestEnableDisable:
    def test_enable_returns_key(self):
        resp = client.get("/sncro/enable")
        assert resp.status_code == 200
        assert "sncro_key" in resp.cookies
        assert len(resp.cookies["sncro_key"]) == 8
        assert resp.cookies["sncro_key"] in resp.text

    def test_enable_preserves_existing_key(self):
        # First enable
        resp1 = client.get("/sncro/enable")
        key1 = resp1.cookies["sncro_key"]

        # Second enable with cookie set
        resp2 = client.get("/sncro/enable", cookies={"sncro_key": key1})
        assert key1 in resp2.text

    def test_disable_clears_cookie(self):
        resp = client.get("/sncro/disable")
        assert resp.status_code == 200
        assert "sncro disabled" in resp.text.lower()


class TestInjection:
    def test_no_injection_without_cookie(self):
        resp = client.get("/")
        assert "agent.js" not in resp.text

    def test_injects_script_with_cookie(self):
        resp = client.get("/", cookies={"sncro_key": "abc12345"})
        assert 'data-key="abc12345"' in resp.text
        assert "agent.js" in resp.text
        assert resp.text.index("agent.js") < resp.text.index("</body>")

    def test_no_injection_on_json_response(self):
        resp = client.get("/api/data", cookies={"sncro_key": "abc12345"})
        assert resp.json() == {"data": 1}
        assert "agent.js" not in resp.text

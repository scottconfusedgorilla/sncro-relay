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
    def test_enable_with_key(self):
        resp = client.get("/sncro/enable/abc12345")
        assert resp.status_code == 200
        assert "sncro_key" in resp.cookies
        assert resp.cookies["sncro_key"] == "abc12345"
        assert "Connected" in resp.text

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

    def test_injection_does_not_corrupt_content_length(self):
        """Injected script makes body larger; Content-Length must match."""
        resp = client.get("/", cookies={"sncro_key": "abc12345"})
        assert resp.status_code == 200
        body_len = len(resp.content)
        content_length = resp.headers.get("content-length")
        if content_length is not None:
            assert int(content_length) == body_len

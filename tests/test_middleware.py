"""Tests for the sncro FastAPI middleware.

Tests the two entry points and the dispatch middleware:
- GET  /sncro/enable/{key}          → confirm page (does NOT set cookies)
- POST /sncro/enable/{key}/confirm  → consumes session at relay, sets cookies
- Dispatch middleware injects agent.js script tag if both cookies are present.

The POST /confirm handler requires an Origin / Sec-Fetch-Site same-origin
header; tests simulate that via the TestClient's default same-origin Origin.
"""

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from middleware import SncroMiddleware, sncro_routes

KEY = "100000001"
BROWSER_SECRET = "0" * 32


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


class TestEnableConfirmPage:
    """GET /sncro/enable/{key} shows a confirm page and does NOT set cookies."""

    def test_get_shows_confirm_page(self):
        resp = client.get(f"/sncro/enable/{KEY}")
        assert resp.status_code == 200
        assert "Allow sncro" in resp.text
        # GET must not set any cookies — only POST /confirm does.
        assert "sncro_key" not in resp.cookies
        assert "sncro_browser_secret" not in resp.cookies

    def test_get_rejects_bad_key(self):
        resp = client.get("/sncro/enable/not-nine-digits")
        assert resp.status_code == 200
        assert "Invalid session code" in resp.text

    def test_security_headers_on_confirm_page(self):
        resp = client.get(f"/sncro/enable/{KEY}")
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in resp.headers.get("Content-Security-Policy", "")

    def test_confirm_post_rejects_cross_site(self):
        # Simulate a cross-site auto-submit attack (NEW-1). Flag it via
        # Sec-Fetch-Site=cross-site; the handler must refuse.
        resp = client.post(f"/sncro/enable/{KEY}/confirm",
                           headers={"Sec-Fetch-Site": "cross-site"})
        assert resp.status_code == 200
        assert "Cross-site request blocked" in resp.text
        assert "sncro_key" not in resp.cookies

    def test_confirm_post_rejects_missing_origin_headers(self):
        # No Origin and no Sec-Fetch-Site at all: also rejected (belt-and-suspenders).
        resp = client.post(f"/sncro/enable/{KEY}/confirm")
        assert resp.status_code == 200
        assert "Cross-site request blocked" in resp.text


class TestDisable:
    def test_disable_page_renders(self):
        resp = client.get("/sncro/disable")
        assert resp.status_code == 200
        assert "sncro disabled" in resp.text.lower()

    def test_disable_has_security_headers(self):
        resp = client.get("/sncro/disable")
        assert resp.headers.get("X-Frame-Options") == "DENY"


class TestInjection:
    """The dispatch middleware injects the script tag when both cookies match the expected shapes."""

    def test_no_injection_without_cookies(self):
        resp = client.get("/")
        assert "agent.js" not in resp.text

    def test_no_injection_with_only_key_cookie(self):
        c = TestClient(make_app())
        c.cookies.set("sncro_key", KEY)
        resp = c.get("/")
        assert "agent.js" not in resp.text

    def test_injects_script_with_both_cookies(self):
        c = TestClient(make_app())
        c.cookies.set("sncro_key", KEY)
        c.cookies.set("sncro_browser_secret", BROWSER_SECRET)
        resp = c.get("/")
        assert "agent.js" in resp.text
        assert f'data-key="{KEY}"' in resp.text
        assert f'data-secret="{BROWSER_SECRET}"' in resp.text
        assert resp.text.index("agent.js") < resp.text.index("</body>")

    def test_rejects_non_nine_digit_key(self):
        c = TestClient(make_app())
        c.cookies.set("sncro_key", "abc12345")  # not 9 digits
        c.cookies.set("sncro_browser_secret", BROWSER_SECRET)
        resp = c.get("/")
        assert "agent.js" not in resp.text

    def test_rejects_non_hex_browser_secret(self):
        c = TestClient(make_app())
        c.cookies.set("sncro_key", KEY)
        c.cookies.set("sncro_browser_secret", "not-hex")
        resp = c.get("/")
        assert "agent.js" not in resp.text

    def test_no_injection_on_json_response(self):
        c = TestClient(make_app())
        c.cookies.set("sncro_key", KEY)
        c.cookies.set("sncro_browser_secret", BROWSER_SECRET)
        resp = c.get("/api/data")
        assert resp.json() == {"data": 1}
        assert "agent.js" not in resp.text

    def test_injection_does_not_corrupt_content_length(self):
        """Injected script makes body larger; Content-Length must match."""
        c = TestClient(make_app())
        c.cookies.set("sncro_key", KEY)
        c.cookies.set("sncro_browser_secret", BROWSER_SECRET)
        resp = c.get("/")
        assert resp.status_code == 200
        body_len = len(resp.content)
        content_length = resp.headers.get("content-length")
        if content_length is not None:
            assert int(content_length) == body_len

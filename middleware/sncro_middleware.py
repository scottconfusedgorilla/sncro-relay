"""
Drop-in sncro middleware for FastAPI projects.

Usage:
    from sncro_middleware import SncroMiddleware, sncro_routes

    app = FastAPI(debug=True)  # ONLY load sncro when debug — see below
    if app.debug:
        app.include_router(sncro_routes)
        app.add_middleware(SncroMiddleware, relay_url="https://relay.sncro.net")
"""

import html
import json
import re
import urllib.request
import urllib.error

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Announced to the relay via X-Sncro-Middleware-Version on /enable calls.
# Bump this when you pull a new version from sncro-relay so the relay can
# warn Claude (via check_session) if a customer app is running an old copy.
SNCRO_MIDDLEWARE_VERSION = "0.9.4"

# Cookies are read by agent.js (must be non-httponly) and only flow same-site.
SNCRO_KEY_COOKIE = "sncro_key"
SNCRO_BROWSER_SECRET_COOKIE = "sncro_browser_secret"
KEY_RE = re.compile(r"^\d{9}$")
SECRET_RE = re.compile(r"^[0-9a-f]{32}$")

# Prevent clickjacking on every sncro-served page. DENY stops framing in
# all browsers (including old ones that ignore CSP); frame-ancestors 'none'
# is the modern equivalent.
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
}


def _secure_html(content: str, status_code: int = 200) -> HTMLResponse:
    """HTMLResponse with clickjacking + referrer-leak defences pre-applied."""
    return HTMLResponse(content=content, status_code=status_code,
                        headers=dict(SECURITY_HEADERS))


class SncroMiddleware(BaseHTTPMiddleware):
    """Injects the sncro agent script into HTML responses when enabled."""

    def __init__(self, app, relay_url: str = "https://relay.sncro.net"):
        super().__init__(app)
        self.relay_url = relay_url.rstrip("/")
        app._sncro_relay_url = self.relay_url

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        key = request.cookies.get(SNCRO_KEY_COOKIE) or ""
        browser_secret = request.cookies.get(SNCRO_BROWSER_SECRET_COOKIE) or ""

        # Reject anything that doesn't match the expected shapes — defence in
        # depth against cookie-tampering attempts that try to break out of the
        # data-* attributes below.
        if not KEY_RE.fullmatch(key) or not SECRET_RE.fullmatch(browser_secret):
            return response

        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return response

        body = b""
        async for chunk in response.body_iterator:
            body += chunk if isinstance(chunk, bytes) else chunk.encode()

        # All three values are validated as digits/hex above — the html.escape
        # is belt-and-suspenders so a future change can't introduce XSS via
        # the data-* attributes.
        tag = (
            f'<script src="{html.escape(self.relay_url, quote=True)}/static/agent.js" '
            f'data-key="{html.escape(key, quote=True)}" '
            f'data-secret="{html.escape(browser_secret, quote=True)}" '
            f'data-relay="{html.escape(self.relay_url, quote=True)}"></script>'
        )
        body_str = body.decode()

        if "</body>" in body_str:
            body_str = body_str.replace("</body>", f"{tag}\n</body>")
        else:
            body_str += tag

        new_headers = {k: v for k, v in response.headers.items()
                       if k.lower() != "content-length"}
        return Response(
            content=body_str,
            status_code=response.status_code,
            headers=new_headers,
            media_type="text/html",
        )


# --- Routes: /sncro/enable and /sncro/disable ---

sncro_routes = APIRouter(prefix="/sncro", tags=["sncro"])


def _normalize_key(key: str) -> str:
    """Strip dashes/spaces from a session key (787-221-713 -> 787221713)."""
    return key.replace("-", "").replace(" ", "").strip()


def _key_is_valid(key: str) -> bool:
    return bool(KEY_RE.fullmatch(key))


def _error_page(title: str, status: str, hint: str) -> HTMLResponse:
    return _secure_html(f"""<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro — {html.escape(title)}</title>
<style>body {{ font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }}
.status {{ font-size: 1.4em; color: #dc2626; margin: 30px 0 10px; }}
.hint {{ color: #666; margin-top: 10px; line-height: 1.6; }}</style></head>
<body><h2>sncro</h2>
<p class="status">{html.escape(status)}</p>
<p class="hint">{hint}</p>
</body></html>""")


def _request_is_same_origin(request: Request) -> bool:
    """CSRF defence for state-changing POSTs.

    Modern browsers send Sec-Fetch-Site on every request; trust it first.
    Fall back to Origin (sent on POSTs by all major browsers). Rejecting
    when neither is present is safer than allowing — real browsers always
    send at least one.
    """
    sec_fetch_site = request.headers.get("sec-fetch-site", "")
    if sec_fetch_site:
        return sec_fetch_site in ("same-origin", "none")
    origin = request.headers.get("origin", "")
    if origin:
        expected = f"{request.url.scheme}://{request.url.netloc}"
        return origin == expected
    return False


@sncro_routes.get("/healthcheck")
async def sncro_healthcheck():
    """Used by the relay to discover the canonical domain for this app."""
    return {"ok": True}


@sncro_routes.get("/version")
async def sncro_version():
    """Report the installed sncro middleware version.

    Exposed so developers and the relay can detect stale middleware copies
    without having to read the file on disk.
    """
    return {"version": SNCRO_MIDDLEWARE_VERSION}


@sncro_routes.get("/enable", response_class=HTMLResponse)
async def sncro_enable_prompt():
    """Show a code-entry form when no key is in the URL."""
    html = """<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro — enter code</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; padding: 0 20px; }
  h2 { margin-bottom: 8px; }
  .hint { color: #666; margin-bottom: 30px; line-height: 1.6; }
  .code-input { display: flex; gap: 12px; justify-content: center; margin: 30px 0; }
  .code-input input {
    width: 70px; height: 70px; font-size: 2em; text-align: center;
    border: 2px solid #ddd; border-radius: 12px; font-family: monospace;
    -moz-appearance: textfield;
  }
  .code-input input::-webkit-outer-spin-button,
  .code-input input::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
  .code-input input:focus { border-color: #2563eb; outline: none; }
  .btn { padding: 12px 24px; font-size: 1em; background: #2563eb; color: white; border: none; border-radius: 8px; cursor: pointer; }
  .btn:hover { background: #1d4ed8; }
</style></head>
<body>
  <h2>sncro</h2>
  <p class="hint">Enter the 9-digit code from Claude</p>
  <div class="code-input">
    <input type="text" inputmode="numeric" maxlength="3" pattern="[0-9]*" id="c1">
    <input type="text" inputmode="numeric" maxlength="3" pattern="[0-9]*" id="c2">
    <input type="text" inputmode="numeric" maxlength="3" pattern="[0-9]*" id="c3">
  </div>
  <button class="btn" onclick="go()">Connect</button>
  <script>
    var inputs = [document.getElementById('c1'), document.getElementById('c2'), document.getElementById('c3')];
    inputs.forEach(function(inp, i) {
      inp.addEventListener('input', function() {
        inp.value = inp.value.replace(/[^0-9]/g, '');
        if (inp.value.length === 3 && i < 2) inputs[i+1].focus();
      });
      inp.addEventListener('keydown', function(e) {
        if (e.key === 'Backspace' && inp.value === '' && i > 0) inputs[i-1].focus();
        if (e.key === 'Enter') go();
      });
      inp.addEventListener('paste', function(e) {
        e.preventDefault();
        var text = (e.clipboardData || window.clipboardData).getData('text').replace(/[^0-9]/g, '');
        if (text.length >= 9) {
          inputs[0].value = text.slice(0, 3);
          inputs[1].value = text.slice(3, 6);
          inputs[2].value = text.slice(6, 9);
          inputs[2].focus();
        }
      });
    });
    inputs[0].focus();
    function go() {
      var code = inputs[0].value + inputs[1].value + inputs[2].value;
      if (code.length === 9) location.href = '/sncro/enable/' + code;
    }
  </script>
</body></html>"""
    return _secure_html(html)


@sncro_routes.get("/enable/{key}", response_class=HTMLResponse)
async def sncro_enable_confirm_page(key: str, request: Request):
    """Show a confirmation page. Does NOT consume the key or set cookies.

    Why this is a separate page from the actual enable: an attacker who has
    the session_secret (because they created the session) could phish a victim
    into clicking /sncro/enable/{key}. Without confirmation, the cookie is set
    silently, agent.js starts pushing data, and the attacker reads the
    victim's live browser via MCP tools. The confirmation gate makes the
    attack require user action ("Allow" click), which a phishing target is
    unlikely to do for a debugging tool they didn't ask for.
    """
    key = _normalize_key(key)
    if not _key_is_valid(key):
        return _error_page("invalid key", "Invalid session code",
                           "Codes are 9 digits (e.g. 787-221-713).<br>Ask Claude for a new code.")

    display = f"{key[0:3]}-{key[3:6]}-{key[6:9]}"
    host = html.escape(request.url.hostname or "this site", quote=True)
    safe_key = html.escape(key, quote=True)
    confirm_html = f"""<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro — allow access?</title>
<style>
  body {{ font-family: system-ui; max-width: 540px; margin: 24px auto; padding: 0 20px; font-size: 16px; }}
  @media (min-width: 600px) {{ body {{ margin: 60px auto; }} }}
  h2 {{ text-align: center; margin-bottom: 8px; }}
  .lead {{ text-align: center; color: #444; margin-bottom: 24px; }}
  .panel {{ background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; margin: 20px 0; }}
  .code {{ font-family: monospace; font-size: 1.6em; font-weight: 700; letter-spacing: 0.05em; text-align: center; color: #111; }}
  .warn {{ color: #92400e; background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 6px; margin: 16px 0; font-size: 0.9em; line-height: 1.5; }}
  .row {{ display: flex; gap: 12px; justify-content: center; margin-top: 24px; }}
  .btn {{ padding: 12px 24px; font-size: 1em; border-radius: 8px; cursor: pointer; border: none; }}
  .btn-allow {{ background: #16a34a; color: white; }}
  .btn-allow:hover {{ background: #15803d; }}
  .btn-deny {{ background: #f3f4f6; color: #374151; border: 1px solid #d1d5db; }}
  .btn-deny:hover {{ background: #e5e7eb; }}
  .meta {{ color: #6b7280; font-size: 0.85em; text-align: center; margin-top: 16px; line-height: 1.6; }}
</style></head>
<body>
  <h2>Allow sncro debugging?</h2>
  <p class="lead">An AI assistant is asking to inspect this browser on <strong>{host}</strong>.</p>

  <div class="panel">
    <div class="code">{display}</div>
  </div>

  <div class="warn">
    <strong>Only allow this if you asked Claude (or another AI) to debug this page.</strong>
    Once allowed, the AI can read what you see, what you type into forms,
    your console errors, and your network activity for the next 30 minutes.
  </div>

  <form method="POST" action="/sncro/enable/{safe_key}/confirm" class="row">
    <button type="submit" class="btn btn-allow">Allow</button>
    <button type="button" class="btn btn-deny" onclick="history.back()">Cancel</button>
  </form>

  <p class="meta">If you didn't expect this, just close the tab. Nothing is enabled until you click Allow.</p>
</body></html>"""
    return _secure_html(confirm_html)


@sncro_routes.post("/enable/{key}/confirm", response_class=HTMLResponse)
async def sncro_enable(key: str, request: Request):
    """Actually enable sncro after the user clicked Allow on the confirm page.

    This is the only entry point that consumes the session and sets cookies.
    Reachable only via a POST form submission — i.e. a deliberate user action,
    not an attacker-supplied link.

    CSRF defence: without the Origin / Sec-Fetch-Site check below, a hidden
    auto-submitting form on evil.com can POST here cross-site; SameSite=Strict
    on the resulting cookies blocks them being *sent* cross-site but not *set*,
    so the victim ends up with a live sncro session seeded by the attacker.
    """
    if not _request_is_same_origin(request):
        return _error_page("cross-site POST blocked", "Cross-site request blocked",
                           "If you meant to enable sncro, open the URL directly in this browser.")

    key = _normalize_key(key)
    if not _key_is_valid(key):
        return _error_page("invalid key", "Invalid session code",
                           "Codes are 9 digits (e.g. 787-221-713).<br>Ask Claude for a new code.")

    relay_url = getattr(request.app, '_sncro_relay_url', 'https://relay.sncro.net')
    browser_secret = ""
    try:
        req = urllib.request.Request(
            f"{relay_url}/session/{key}/enable",
            method="POST",
            data=b"",
            headers={"X-Sncro-Middleware-Version": SNCRO_MIDDLEWARE_VERSION},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            payload = json.loads(r.read().decode())
        browser_secret = payload.get("browser_secret", "")
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return _error_page("key already used", "This key has already been used",
                               "Each session key can only be used in one browser.<br>Ask Claude to create a new session.")
        if e.code == 404:
            return _error_page("key not found", "Session not found or expired",
                               "Sessions last 30 minutes. Ask Claude to create a new session.")
        return _error_page("relay error", "Could not enable sncro",
                           "The sncro relay returned an unexpected error. Try again.")
    except Exception:
        return _error_page("relay unreachable", "Could not reach the sncro relay",
                           "Check your network and try again.")

    if not SECRET_RE.fullmatch(browser_secret):
        return _error_page("relay error", "Invalid response from relay",
                           "The relay did not return a valid browser secret.")

    html_body = """<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro enabled</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
  .status { font-size: 1.4em; color: #16a34a; margin: 30px 0 10px; }
  .hint { color: #666; margin-top: 10px; line-height: 1.6; }
  .countdown { font-size: 1.1em; color: #333; margin-top: 20px; }
  .countdown span { font-weight: bold; font-size: 1.3em; }
  a { color: #2563eb; }
</style></head>
<body>
  <h2>sncro</h2>
  <p class="status">Connected!</p>
  <p class="hint">Please let Claude know that sncro is active.</p>
  <p class="countdown">Returning to previous page in <span id="count">5</span> seconds...</p>
  <p class="hint"><a href="/sncro/disable">Disable sncro</a></p>
  <script>
    var n = 5;
    var el = document.getElementById('count');
    var t = setInterval(function() {
      n--;
      el.textContent = n;
      if (n <= 0) {
        clearInterval(t);
        var ref = document.referrer;
        if (ref && ref.indexOf('/sncro/') === -1) location.href = ref;
        else location.href = '/';
      }
    }, 1000);
  </script>
</body></html>"""

    response = HTMLResponse(content=html_body, headers=dict(SECURITY_HEADERS))
    # Cookies are non-httponly so agent.js can read them. Defence is via:
    #   - secure: HTTPS-only
    #   - samesite=strict: don't flow on cross-site requests (helps mitigate C-1)
    #   - 30-minute max_age: matches relay session lifetime
    cookie_kwargs = dict(httponly=False, secure=True, samesite="strict", max_age=1800, path="/")
    response.set_cookie(SNCRO_KEY_COOKIE, key, **cookie_kwargs)
    response.set_cookie(SNCRO_BROWSER_SECRET_COOKIE, browser_secret, **cookie_kwargs)
    return response


@sncro_routes.get("/enable/{key}/qrcode", response_class=HTMLResponse)
async def sncro_qrcode(key: str, request: Request):
    """Show a QR code for the enable URL — each key is single-use per device."""
    key = _normalize_key(key)
    if not _key_is_valid(key):
        return _error_page("invalid key", "Invalid session code",
                           "Codes are 9 digits.<br>Ask Claude for a new code.")
    base = str(request.base_url).rstrip("/")
    enable_url = f"{base}/sncro/enable/{key}"
    html = """<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro — scan to enable</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 60px auto; text-align: center;
         background: #0a0e1a; color: #e0e0e0; }
  .qr-wrap { background: #fff; display: inline-block; padding: 24px; border-radius: 12px; margin: 20px 0; }
  .hint { color: #888; margin-top: 16px; line-height: 1.6; font-size: 0.9em; }
  .countdown { color: #888; margin-top: 12px; }
  .countdown span { font-weight: bold; color: #e0e0e0; }
  a { color: #4f8cff; }
  canvas { display: block; }
</style>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
</head>
<body>
  <h2>sncro</h2>
  <p>Scan to enable on your device</p>
  <div class="qr-wrap"><canvas id="qr"></canvas></div>
  <p class="hint">This key can only be used once.<br>Ask Claude for a new session to debug another device.</p>
  <p class="countdown">This page closes in <span id="count">30</span> seconds</p>
  <script>
    var qr = qrcode(0, 'M');
    qr.addData('ENABLE_URL');
    qr.make();
    var canvas = document.getElementById('qr');
    var ctx = canvas.getContext('2d');
    var size = qr.getModuleCount();
    var scale = 8;
    canvas.width = size * scale;
    canvas.height = size * scale;
    for (var r = 0; r < size; r++)
      for (var c = 0; c < size; c++)
        if (qr.isDark(r, c)) {
          ctx.fillStyle = '#000';
          ctx.fillRect(c * scale, r * scale, scale, scale);
        }

    var n = 30;
    var el = document.getElementById('count');
    var t = setInterval(function() {
      n--;
      el.textContent = n;
      if (n <= 0) {
        clearInterval(t);
        var ref = document.referrer;
        if (ref && ref.indexOf('/sncro/') === -1) location.href = ref;
        else location.href = '/';
      }
    }, 1000);
  </script>
</body></html>""".replace("ENABLE_URL", enable_url)

    return _secure_html(html)


@sncro_routes.get("/disable", response_class=HTMLResponse)
async def sncro_disable():
    """Disable sncro for this browser session."""
    html = """<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro disabled</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
</style></head>
<body>
  <h2>sncro disabled</h2>
  <p>The agent script will no longer be injected.</p>
</body></html>"""

    response = HTMLResponse(content=html, headers=dict(SECURITY_HEADERS))
    response.delete_cookie(SNCRO_KEY_COOKIE, path="/")
    response.delete_cookie(SNCRO_BROWSER_SECRET_COOKIE, path="/")
    return response

"""
Drop-in sncro middleware for FastAPI projects.

Usage:
    from sncro.middleware import SncroMiddleware, sncro_routes

    app = FastAPI()
    app.include_router(sncro_routes)
    app.add_middleware(SncroMiddleware, relay_url="https://sncro.net")
"""

import secrets
import urllib.request
import urllib.error

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware

SNCRO_COOKIE = "sncro_key"
SCRIPT_TAG = '<script src="{relay}/static/agent.js" data-key="{key}" data-relay="{relay}"></script>'


class SncroMiddleware(BaseHTTPMiddleware):
    """Injects the sncro agent script into HTML responses when enabled."""

    def __init__(self, app, relay_url: str = "https://sncro.net"):
        super().__init__(app)
        self.relay_url = relay_url.rstrip("/")
        app._sncro_relay_url = self.relay_url

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        key = request.cookies.get(SNCRO_COOKIE)
        if not key:
            return response

        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return response

        # Read body and inject script before </body>
        body = b""
        async for chunk in response.body_iterator:
            body += chunk if isinstance(chunk, bytes) else chunk.encode()

        tag = SCRIPT_TAG.format(relay=self.relay_url, key=key)
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


@sncro_routes.get("/healthcheck")
async def sncro_healthcheck():
    """Used by the relay to discover the canonical domain for this app."""
    return {"ok": True}


@sncro_routes.get("/enable/{key}", response_class=HTMLResponse)
async def sncro_enable(key: str, request: Request):
    """Enable sncro with a key from Claude's create_session tool."""
    relay_url = getattr(request.app, '_sncro_relay_url', 'https://relay.sncro.net')
    try:
        req = urllib.request.Request(f"{relay_url}/session/{key}/consume", method="POST", data=b"")
        urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return HTMLResponse(content="""<!DOCTYPE html>
<html><head><title>sncro — key already used</title>
<style>body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
.status { font-size: 1.4em; color: #dc2626; margin: 30px 0 10px; }
.hint { color: #666; margin-top: 10px; line-height: 1.6; }</style></head>
<body><h2>sncro</h2>
<p class="status">This key has already been used</p>
<p class="hint">Each session key can only be used in one browser.<br>Ask Claude to create a new session.</p>
</body></html>""")
        if e.code == 404:
            return HTMLResponse(content="""<!DOCTYPE html>
<html><head><title>sncro — key not found</title>
<style>body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
.status { font-size: 1.4em; color: #dc2626; margin: 30px 0 10px; }
.hint { color: #666; margin-top: 10px; line-height: 1.6; }</style></head>
<body><h2>sncro</h2>
<p class="status">Session not found or expired</p>
<p class="hint">Sessions last 30 minutes. Ask Claude to create a new session.</p>
</body></html>""")
    except Exception:
        pass  # If relay is unreachable, allow enabling anyway

    html = """<!DOCTYPE html>
<html><head><title>sncro enabled</title>
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

    response = HTMLResponse(content=html)
    response.set_cookie(SNCRO_COOKIE, key, httponly=False, samesite="lax")
    return response


@sncro_routes.get("/enable/{key}/qrcode", response_class=HTMLResponse)
async def sncro_qrcode(key: str, request: Request):
    """Show a QR code for the enable URL — each key is single-use per device."""
    base = str(request.base_url).rstrip("/")
    enable_url = f"{base}/sncro/enable/{key}"
    html = """<!DOCTYPE html>
<html><head><title>sncro — scan to enable</title>
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

    return HTMLResponse(content=html)


@sncro_routes.get("/disable", response_class=HTMLResponse)
async def sncro_disable():
    """Disable sncro for this browser session."""
    html = """<!DOCTYPE html>
<html><head><title>sncro disabled</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
</style></head>
<body>
  <h2>sncro disabled</h2>
  <p>The agent script will no longer be injected.</p>
</body></html>"""

    response = HTMLResponse(content=html)
    response.delete_cookie(SNCRO_COOKIE)
    return response

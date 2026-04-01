"""
Drop-in sncro middleware for FastAPI projects.

Usage:
    from sncro.middleware import SncroMiddleware, sncro_routes

    app = FastAPI()
    app.include_router(sncro_routes)
    app.add_middleware(SncroMiddleware, relay_url="https://sncro.net")
"""

import secrets

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


@sncro_routes.get("/enable/{key}", response_class=HTMLResponse)
async def sncro_enable(key: str):
    """Enable sncro with a key from Claude's create_session tool."""
    html = f"""<!DOCTYPE html>
<html><head><title>sncro enabled</title>
<style>
  body {{ font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }}
  .key {{ font-size: 2em; font-family: monospace; padding: 20px; background: #f0f0f0;
          border-radius: 8px; margin: 20px 0; letter-spacing: 0.1em; user-select: all; }}
  .hint {{ color: #666; margin-top: 20px; }}
  a {{ color: #2563eb; }}
</style></head>
<body>
  <h2>sncro is active</h2>
  <p>Session key: <span class="key">{key}</span></p>
  <p class="hint">Claude Code is now connected to this browser session.<br>
  <a href="/sncro/disable">Disable</a></p>
</body></html>"""

    response = HTMLResponse(content=html)
    response.set_cookie(SNCRO_COOKIE, key, httponly=True, samesite="lax")
    return response


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

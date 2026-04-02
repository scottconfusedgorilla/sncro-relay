"""
Drop-in sncro middleware for Flask projects.

Usage:
    from sncro_flask import init_sncro

    app = Flask(__name__)
    init_sncro(app, relay_url="https://relay.sncro.net")
"""

from flask import Flask, request, make_response

SNCRO_COOKIE = "sncro_key"
SCRIPT_TAG = '<script src="{relay}/static/agent.js" data-key="{key}" data-relay="{relay}"></script>'


def init_sncro(app: Flask, relay_url: str = "https://relay.sncro.net"):
    """Initialize sncro on a Flask app. Adds routes and response injection."""

    relay = relay_url.rstrip("/")

    @app.route("/sncro/enable/<key>")
    def sncro_enable(key):
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
        resp = make_response(html)
        resp.set_cookie(SNCRO_COOKIE, key, httponly=True, samesite="Lax")
        return resp

    @app.route("/sncro/disable")
    def sncro_disable():
        html = """<!DOCTYPE html>
<html><head><title>sncro disabled</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
</style></head>
<body>
  <h2>sncro disabled</h2>
  <p>The agent script will no longer be injected.</p>
</body></html>"""
        resp = make_response(html)
        resp.delete_cookie(SNCRO_COOKIE)
        return resp

    @app.after_request
    def sncro_inject(response):
        key = request.cookies.get(SNCRO_COOKIE)
        if not key:
            return response

        content_type = response.content_type or ""
        if "text/html" not in content_type:
            return response

        data = response.get_data(as_text=True)
        tag = SCRIPT_TAG.format(relay=relay, key=key)

        if "</body>" in data:
            data = data.replace("</body>", f"{tag}\n</body>")
        else:
            data += tag

        response.set_data(data)
        response.headers.pop("Content-Length", None)
        return response

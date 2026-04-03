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
        resp = make_response(html)
        resp.set_cookie(SNCRO_COOKIE, key, httponly=False, samesite="Lax")
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

        # Skip direct passthrough responses (e.g. send_from_directory)
        if response.direct_passthrough:
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

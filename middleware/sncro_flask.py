"""
Drop-in sncro middleware for Flask projects.

Usage:
    from sncro_flask import init_sncro

    app = Flask(__name__)
    init_sncro(app, relay_url="https://relay.sncro.net")
"""

import urllib.request
import urllib.error

from flask import Flask, request, make_response

SNCRO_COOKIE = "sncro_key"
SCRIPT_TAG = '<script src="{relay}/static/agent.js" data-key="{key}" data-relay="{relay}"></script>'


def init_sncro(app: Flask, relay_url: str = "https://relay.sncro.net"):
    """Initialize sncro on a Flask app. Adds routes and response injection."""

    relay = relay_url.rstrip("/")

    @app.route("/sncro/enable/<key>")
    def sncro_enable(key):
        # Try to consume the key (single-use)
        try:
            req = urllib.request.Request(f"{relay}/session/{key}/consume", method="POST", data=b"")
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            if e.code == 409:
                return """<!DOCTYPE html>
<html><head><title>sncro — key already used</title>
<style>body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
.status { font-size: 1.4em; color: #dc2626; margin: 30px 0 10px; }
.hint { color: #666; margin-top: 10px; line-height: 1.6; }</style></head>
<body><h2>sncro</h2>
<p class="status">This key has already been used</p>
<p class="hint">Each session key can only be used in one browser.<br>Ask Claude to create a new session.</p>
</body></html>"""
            if e.code == 404:
                return """<!DOCTYPE html>
<html><head><title>sncro — key not found</title>
<style>body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
.status { font-size: 1.4em; color: #dc2626; margin: 30px 0 10px; }
.hint { color: #666; margin-top: 10px; line-height: 1.6; }</style></head>
<body><h2>sncro</h2>
<p class="status">Session not found or expired</p>
<p class="hint">Sessions last 30 minutes. Ask Claude to create a new session.</p>
</body></html>"""
        except Exception:
            pass

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

    @app.route("/sncro/enable/<key>/qrcode")
    def sncro_qrcode(key):
        enable_url = f"{request.host_url.rstrip('/')}/sncro/enable/{key}"
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
        return html

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

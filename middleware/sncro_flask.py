"""
Drop-in sncro middleware for Flask projects.

Usage:
    from sncro_flask import init_sncro

    app = Flask(__name__)
    if app.debug:
        init_sncro(app, relay_url="https://relay.sncro.net")
"""

import html as _html
import json
import re
import urllib.request
import urllib.error

from flask import Flask, request, make_response

# Cookies are read by agent.js (must be non-httponly) and only flow same-site.
SNCRO_KEY_COOKIE = "sncro_key"
SNCRO_BROWSER_SECRET_COOKIE = "sncro_browser_secret"
KEY_RE = re.compile(r"^\d{9}$")
SECRET_RE = re.compile(r"^[0-9a-f]{32}$")


def _normalize_key(k):
    return k.replace("-", "").replace(" ", "").strip()


def _key_is_valid(k):
    return bool(KEY_RE.fullmatch(k))


def _error_page(title, status, hint):
    return f"""<!DOCTYPE html>
<html><head><title>sncro — {_html.escape(title)}</title>
<style>body {{ font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }}
.status {{ font-size: 1.4em; color: #dc2626; margin: 30px 0 10px; }}
.hint {{ color: #666; margin-top: 10px; line-height: 1.6; }}</style></head>
<body><h2>sncro</h2>
<p class="status">{_html.escape(status)}</p>
<p class="hint">{hint}</p>
</body></html>"""


def init_sncro(app: Flask, relay_url: str = "https://relay.sncro.net"):
    """Initialize sncro on a Flask app. Adds routes and response injection."""

    relay = relay_url.rstrip("/")

    @app.route("/sncro/healthcheck")
    def sncro_healthcheck():
        """Used by the relay to discover the canonical domain for this app."""
        return {"ok": True}

    @app.route("/sncro/enable")
    def sncro_enable_prompt():
        """Show a code-entry form when no key is in the URL."""
        return """<!DOCTYPE html>
<html><head><title>sncro — enter code</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; padding: 0 20px; }
  h2 { margin-bottom: 8px; }
  .hint { color: #666; margin-bottom: 30px; line-height: 1.6; }
  .code-input { display: flex; gap: 12px; justify-content: center; margin: 30px 0; }
  .code-input input {
    width: 70px; height: 70px; font-size: 2em; text-align: center;
    border: 2px solid #ddd; border-radius: 12px; font-family: monospace;
  }
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

    @app.route("/sncro/enable/<key>")
    def sncro_enable(key):
        """Enable sncro. See FastAPI middleware docstring for full notes."""
        key = _normalize_key(key)
        if not _key_is_valid(key):
            return _error_page("invalid key", "Invalid session code",
                               "Codes are 9 digits (e.g. 787-221-713).<br>Ask Claude for a new code.")

        browser_secret = ""
        try:
            req = urllib.request.Request(f"{relay}/session/{key}/enable", method="POST", data=b"")
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
            # Fail closed — don't set a cookie if we couldn't verify the key.
            return _error_page("relay unreachable", "Could not reach the sncro relay",
                               "Check your network and try again.")

        if not SECRET_RE.fullmatch(browser_secret):
            return _error_page("relay error", "Invalid response from relay",
                               "The relay did not return a valid browser secret.")

        body = """<!DOCTYPE html>
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
        resp = make_response(body)
        cookie_kwargs = dict(httponly=False, secure=True, samesite="Strict", max_age=1800, path="/")
        resp.set_cookie(SNCRO_KEY_COOKIE, key, **cookie_kwargs)
        resp.set_cookie(SNCRO_BROWSER_SECRET_COOKIE, browser_secret, **cookie_kwargs)
        return resp

    @app.route("/sncro/enable/<key>/qrcode")
    def sncro_qrcode(key):
        key = _normalize_key(key)
        if not _key_is_valid(key):
            return _error_page("invalid key", "Invalid session code",
                               "Codes are 9 digits.<br>Ask Claude for a new code.")
        enable_url = f"{request.host_url.rstrip('/')}/sncro/enable/{key}"
        body = """<!DOCTYPE html>
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
        return body

    @app.route("/sncro/disable")
    def sncro_disable():
        body = """<!DOCTYPE html>
<html><head><title>sncro disabled</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
</style></head>
<body>
  <h2>sncro disabled</h2>
  <p>The agent script will no longer be injected.</p>
</body></html>"""
        resp = make_response(body)
        resp.delete_cookie(SNCRO_KEY_COOKIE, path="/")
        resp.delete_cookie(SNCRO_BROWSER_SECRET_COOKIE, path="/")
        return resp

    @app.after_request
    def sncro_inject(response):
        key = request.cookies.get(SNCRO_KEY_COOKIE) or ""
        browser_secret = request.cookies.get(SNCRO_BROWSER_SECRET_COOKIE) or ""

        # Reject anything that doesn't match the expected shapes — defence in
        # depth against cookie-tampering attempts.
        if not KEY_RE.fullmatch(key) or not SECRET_RE.fullmatch(browser_secret):
            return response

        content_type = response.content_type or ""
        if "text/html" not in content_type:
            return response

        # Skip direct passthrough responses (e.g. send_from_directory)
        if response.direct_passthrough:
            return response

        data = response.get_data(as_text=True)
        tag = (
            f'<script src="{_html.escape(relay, quote=True)}/static/agent.js" '
            f'data-key="{_html.escape(key, quote=True)}" '
            f'data-secret="{_html.escape(browser_secret, quote=True)}" '
            f'data-relay="{_html.escape(relay, quote=True)}"></script>'
        )

        if "</body>" in data:
            data = data.replace("</body>", f"{tag}\n</body>")
        else:
            data += tag

        response.set_data(data)
        response.headers.pop("Content-Length", None)
        return response

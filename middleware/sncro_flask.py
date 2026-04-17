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

# Prevent clickjacking on every sncro-served page. DENY stops framing in
# all browsers (including old ones that ignore CSP); frame-ancestors 'none'
# is the modern equivalent.
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
}


def _secure_html(body, status=200):
    """Flask response with clickjacking + referrer-leak defences pre-applied."""
    resp = make_response(body, status)
    for name, value in SECURITY_HEADERS.items():
        resp.headers[name] = value
    return resp


def _normalize_key(k):
    return k.replace("-", "").replace(" ", "").strip()


def _key_is_valid(k):
    return bool(KEY_RE.fullmatch(k))


def _request_is_same_origin():
    """CSRF defence for state-changing POSTs.

    Sec-Fetch-Site is the reliable modern signal; all evergreen browsers
    send it. Origin is a fallback (sent on POSTs by all major browsers).
    Rejecting when neither is present is safer than allowing.
    """
    sec_fetch_site = request.headers.get("Sec-Fetch-Site", "")
    if sec_fetch_site:
        return sec_fetch_site in ("same-origin", "none")
    origin = request.headers.get("Origin", "")
    if origin:
        expected = f"{request.scheme}://{request.host}"
        return origin == expected
    return False


def _error_page(title, status, hint):
    return _secure_html(f"""<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro — {_html.escape(title)}</title>
<style>body {{ font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }}
.status {{ font-size: 1.4em; color: #dc2626; margin: 30px 0 10px; }}
.hint {{ color: #666; margin-top: 10px; line-height: 1.6; }}</style></head>
<body><h2>sncro</h2>
<p class="status">{_html.escape(status)}</p>
<p class="hint">{hint}</p>
</body></html>""")


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
        return _secure_html("""<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro — enter code</title>
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
</body></html>""")

    @app.route("/sncro/enable/<key>")
    def sncro_enable_confirm_page(key):
        """Show a confirmation page. Does NOT consume the key or set cookies.

        Why a confirmation step: an attacker who created the session has the
        session_secret. If they can phish a victim into clicking
        /sncro/enable/{key} on the victim's app, the cookie is set and
        agent.js starts pushing live data — which the attacker can read via
        MCP tools. Requiring an explicit Allow click means a phishing target
        won't grant access by accident.
        """
        key = _normalize_key(key)
        if not _key_is_valid(key):
            return _error_page("invalid key", "Invalid session code",
                               "Codes are 9 digits (e.g. 787-221-713).<br>Ask Claude for a new code.")

        display = f"{key[0:3]}-{key[3:6]}-{key[6:9]}"
        host = _html.escape(request.host or "this site", quote=True)
        safe_key = _html.escape(key, quote=True)
        return _secure_html(f"""<!DOCTYPE html>
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
</body></html>""")

    @app.route("/sncro/enable/<key>/confirm", methods=["POST"])
    def sncro_enable(key):
        """Actually enable sncro after the user clicked Allow on the confirm page.

        CSRF defence: without the Origin / Sec-Fetch-Site check below, a hidden
        auto-submitting form on evil.com can POST here cross-site; SameSite=Strict
        on the resulting cookies blocks them being *sent* cross-site but not *set*,
        so the victim ends up with a live sncro session seeded by the attacker.
        """
        if not _request_is_same_origin():
            return _error_page("cross-site POST blocked", "Cross-site request blocked",
                               "If you meant to enable sncro, open the URL directly in this browser.")

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
            return _error_page("relay unreachable", "Could not reach the sncro relay",
                               "Check your network and try again.")

        if not SECRET_RE.fullmatch(browser_secret):
            return _error_page("relay error", "Invalid response from relay",
                               "The relay did not return a valid browser secret.")

        body = """<!DOCTYPE html>
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
        resp = _secure_html(body)
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
        return _secure_html(body)

    @app.route("/sncro/disable")
    def sncro_disable():
        body = """<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>sncro disabled</title>
<style>
  body { font-family: system-ui; max-width: 500px; margin: 80px auto; text-align: center; }
</style></head>
<body>
  <h2>sncro disabled</h2>
  <p>The agent script will no longer be injected.</p>
</body></html>"""
        resp = _secure_html(body)
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

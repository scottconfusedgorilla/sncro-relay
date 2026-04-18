# Contributing

Thanks for considering a contribution. The highest-impact thing you can contribute is **a plugin for a new framework** — Django, Rails, Express, Next.js, ASP.NET, Go, Laravel, anything with HTTP middleware.

## Quick start

```bash
git clone https://github.com/scottconfusedgorilla/sncro-relay.git
cd sncro-relay
pip install -r requirements.txt
pytest
```

44 tests should pass.

## Building a plugin for a new framework

A sncro plugin has **two jobs**:

1. Serve five routes under `/sncro/*` on the customer's app
2. Inject a `<script>` tag into HTML responses when the right cookies are set

Both existing plugins ([sncro_middleware.py](middleware/sncro_middleware.py) for FastAPI, [sncro_flask.py](middleware/sncro_flask.py) for Flask) are ~400 lines each and implement exactly this spec. Read one of them first — it's the clearest starting point.

### Routes the plugin must serve

| Method | Path | What it does |
|---|---|---|
| `GET` | `/sncro/enable/{key}` | Shows a **confirmation page** ("Allow sncro debugging?"). Does NOT set cookies, does NOT call the relay. Rejects keys that don't match `\d{9}`. |
| `GET` | `/sncro/enable` | Shows a code-entry form (for typing the 9-digit code on a separate device). |
| `GET` | `/sncro/enable/{key}/qrcode` | Shows a QR code of the enable URL, for scanning from a mobile device. |
| `POST` | `/sncro/enable/{key}/confirm` | **The only state-changing endpoint.** Calls `POST {relay}/session/{key}/enable`, gets a `browser_secret`, sets the `sncro_key` + `sncro_browser_secret` cookies, shows a "Connected!" page. |
| `GET` | `/sncro/disable` | Clears the cookies, shows a "Disabled" page. |
| `GET` | `/sncro/healthcheck` | Returns `{"ok": true}`. Used by the relay to probe the canonical domain of the customer's app. |

### Cookies

When the enable flow succeeds, the plugin sets two cookies:

| Cookie | Value | Attributes |
|---|---|---|
| `sncro_key` | 9 digits (e.g. `787221713`) | `secure`, `samesite=strict`, `max_age=1800`, `path=/`, **NOT** `httponly` |
| `sncro_browser_secret` | 32 lowercase hex characters | Same attributes as above |

Both cookies are non-httponly because agent.js reads them. Defence-in-depth is via `samesite=strict` (blocks cross-site send) + `secure` (HTTPS only) + 30-minute expiry.

### Script injection

On every HTML response, if both cookies are present AND match the expected shape, append this tag before `</body>`:

```html
<script src="{RELAY_URL}/static/agent.js"
        data-key="{key}"
        data-secret="{browser_secret}"
        data-relay="{RELAY_URL}"></script>
```

Rules:
- Only inject into responses where `Content-Type` starts with `text/html`
- Validate cookies against regex before injecting: `^\d{9}$` for the key, `^[0-9a-f]{32}$` for the secret
- HTML-escape the values when building the tag
- Strip any stale `Content-Length` header after injection (the body is now longer)

### Security must-haves

These are non-negotiable. Every plugin must:

1. **CSRF defence on POST `/sncro/enable/{key}/confirm`** — reject the request if `Sec-Fetch-Site` is not one of `same-origin` / `none`, OR (fallback) if `Origin` doesn't match the request's own origin. Without this, an attacker's hidden auto-submit form can seed cookies on the victim's browser silently.
2. **`X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`** on every sncro-served page. Defends against clickjacking on the confirm page.
3. **`Referrer-Policy: no-referrer`** on every sncro-served page. Avoids leaking session keys via the Referer header to third parties.
4. **Strict regex validation** on the session key (`\d{9}`) and browser secret (`[0-9a-f]{32}`) at every boundary: URL path params, cookie reads. Reject before the value touches anything downstream.
5. **Fail closed when the relay is unreachable.** Don't set cookies on a key whose enable flow you couldn't complete end-to-end.
6. **`debug`-only activation.** The plugin's routes and injection should only be wired when the app is in debug mode. Example: `if app.debug:` for FastAPI; framework-specific equivalent otherwise.

### Testing your plugin

Copy `tests/test_middleware.py` or `tests/test_e2e_fastapi.py` and adapt to your framework's test harness. The test suite covers:
- Confirm-page behaviour (no cookies on GET)
- Cross-site POST rejection
- Clickjacking headers present
- Injection only with both valid cookies
- Non-9-digit key rejection
- Non-hex secret rejection
- JSON responses not injected
- `Content-Length` integrity after injection

We will not merge a plugin without equivalent test coverage.

## Pull request checklist

- [ ] Tests pass: `pytest`
- [ ] New plugin includes a test file equivalent to `tests/test_middleware.py`
- [ ] Security checklist items above all present
- [ ] README updated with install instructions for the new framework
- [ ] No secrets, credentials, or `.env` contents in any commit (enforced by gitleaks on CI eventually)

## Other ways to help

- **Bug reports**: open an issue. Reproducible test case is ideal.
- **Security issues**: see [SECURITY.md](SECURITY.md) — do not open a public issue.
- **Documentation improvements**: very welcome. The READMEs are terser than they should be.
- **MCP client testing**: if you use sncro with an MCP client other than Claude Code / Claude Desktop, we'd love to know what works and what breaks.

## Code of conduct

Be kind, be specific, assume good faith. Standard PEP 8 for Python. Match the existing style within each file.

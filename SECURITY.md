# Security policy

## Reporting a vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Instead, report them via one of:

- Email: **scott@confusedgorilla.com**
- GitHub Security Advisories: [Report a vulnerability](https://github.com/scottconfusedgorilla/sncro-relay/security/advisories/new)

Please include:
- A description of the vulnerability
- Steps to reproduce
- What an attacker could achieve
- Any suggested fix, if you have one

You can expect an acknowledgement within 72 hours. We'll coordinate disclosure with you.

## Scope

In scope:
- The relay server (`relay/`)
- The framework plugins (`middleware/`)
- The browser-side agent (`relay/static/agent.js`)
- The MCP protocol surface

Out of scope (separate repo, separate report paths):
- The `sncro.net` dashboard, auth, billing, and admin code
- Issues that require the attacker to have already compromised the developer's machine

## Threat model

sncro is a browser debugging tool for developers. The core threat model is:
- **T1** Cross-project leak: attacker reads DOM / console of a victim's session
- **T2** Auth bypass: unauthenticated access to session data
- **T7** Session hijack / fixation: attacker tricks a victim into enabling a session the attacker controls

The codebase has been through a static review (see commit history, builds 084–093, which implemented responses to every Critical and High finding). Known acceptances:
- `M-3 accepted`: the `sncro_key` and `sncro_browser_secret` cookies are `httponly=False` because agent.js reads them. Impact is bounded by the customer's app already owning the origin; XSS on the customer app already means game-over for that origin regardless.

## Security-relevant design

- **Three-secret auth model.** `session_key` (9 digits, public) + `session_secret` (32 hex, MCP-only) + `browser_secret` (32 hex, agent.js-only, set via the enable flow). Secrets are compared with `secrets.compare_digest`. See [relay/store.py](relay/store.py).
- **CSRF defence on the enable flow.** The `POST /sncro/enable/{key}/confirm` handler rejects cross-site requests via `Sec-Fetch-Site` / `Origin`. See [middleware/sncro_middleware.py](middleware/sncro_middleware.py).
- **Clickjacking defence.** All sncro-served pages carry `X-Frame-Options: DENY` + `Content-Security-Policy: frame-ancestors 'none'`.
- **SSRF defence.** The relay's domain-probe path rejects private/loopback/link-local addresses and reserved TLDs before issuing any HTTP request. `follow_redirects=False`.
- **Rate limiting.** Per-IP limits via `slowapi`, keyed on the rightmost `X-Forwarded-For` entry (Railway-appropriate). See [relay/main.py](relay/main.py).
- **Debug-only activation.** Both middlewares are expected to be wired inside `if app.debug:` blocks, so sncro ships zero code into production builds.

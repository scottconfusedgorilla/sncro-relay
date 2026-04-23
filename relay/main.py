"""sncro relay — keyed long-poll rendezvous server + MCP server."""

import asyncio
import ipaddress
import os
import re
import secrets
import socket
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from mcp.server.transport_security import TransportSecuritySettings

from relay.store import SessionStore

# GitHub allows [A-Za-z0-9-] up to 39 chars; we're slightly more permissive
# (underscore, 40 chars) to cover non-GitHub git configs. Anything else is
# rejected at the MCP boundary so it can never reach the DB — blocks stored
# XSS via attacker-supplied git_user (see NEW-5).
_GIT_USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def _client_ip(request: Request) -> str:
    """Rate-limit key: real client IP from X-Forwarded-For (Railway is behind a
    proxy, so request.client.host is the proxy's IP). Falls back to the default.

    Uses the RIGHTMOST entry — Railway's Envoy appends the TCP source to
    X-Forwarded-For rather than replacing it, so the leftmost value is
    attacker-controlled (a client can send X-Forwarded-For: 1.2.3.4 and the
    real IP is appended after). Taking [-1] ensures the value is the one
    Railway itself recorded. Requires exactly one trusted proxy hop — if a
    second reverse proxy (e.g. Cloudflare) is added later, switch to its
    dedicated header (CF-Connecting-IP) or take [-2]. See NEW-4 in the
    blackhat/2 Phase 1c review.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return get_remote_address(request)


# Global defaults are generous; tighter per-route limits are applied via
# @limiter.limit(...) below on sensitive endpoints.
limiter = Limiter(key_func=_client_ip, default_limits=["600/minute"])

# Cache resolved domains for 5 minutes
_domain_cache: dict[str, tuple[str, float]] = {}
DOMAIN_CACHE_TTL = 300  # seconds

# SSRF guard — reserved TLDs that should never be probed.
_BLOCKED_TLDS = (".internal", ".local", ".localhost", ".onion", ".test", ".invalid", ".example")


def _hostname_is_safe(hostname: str) -> bool:
    """SSRF defence — reject anything that resolves to a private/loopback/link-local address.

    Without this, a customer can register a domain that resolves to (or
    redirects to) an internal IP and trick the relay into probing it.
    The relay process holds SUPABASE_SERVICE_ROLE_KEY in its env, so any
    internal-network probe is a real concern.
    """
    if not hostname:
        return False
    h = hostname.lower().strip()
    if any(h.endswith(tld) for tld in _BLOCKED_TLDS):
        return False
    # Bare 'localhost'
    if h == "localhost":
        return False
    # Resolve all A/AAAA records and reject if any are private/loopback/etc.
    try:
        addrinfo = socket.getaddrinfo(h, None)
    except Exception:
        # Can't resolve: refuse rather than guess.
        return False
    for family, _type, _proto, _canon, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False
    return True


def _safe_get(client, url: str):
    """GET that validates the host BEFORE making the request, and refuses to
    follow cross-host redirects (must follow_redirects=False on client)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        return None
    if not _hostname_is_safe(parsed.hostname or ""):
        return None
    try:
        return client.get(url)
    except Exception:
        return None


def _resolve_domain(raw_domain: str) -> str:
    """Probe the middleware healthcheck to find the canonical domain.

    Tries the stored domain, then common www/non-www variants, then a
    one-hop redirect from the root. All probes are guarded by
    _hostname_is_safe — no internal addresses, no reserved TLDs.
    Redirects are NOT auto-followed; we do at most one explicit hop and
    re-check the host of the new target before fetching."""
    import httpx

    now = time.time()
    cached = _domain_cache.get(raw_domain)
    if cached and now - cached[1] < DOMAIN_CACHE_TTL:
        return cached[0]

    if not raw_domain.startswith("http"):
        url = f"https://{raw_domain}"
    else:
        url = raw_domain

    # Try the stored domain, then common variants
    base = url.rstrip("/")
    candidates = [base]

    # Add www variant if not present, or non-www if www is present
    domain_part = base.replace("https://", "").replace("http://", "")
    if domain_part.startswith("www."):
        candidates.append(f"https://{domain_part[4:]}")
    else:
        candidates.append(f"https://www.{domain_part}")

    with httpx.Client(follow_redirects=False, timeout=5) as client:
        for candidate in candidates:
            resp = _safe_get(client, f"{candidate}/sncro/healthcheck")
            if resp is not None and resp.status_code == 200:
                _domain_cache[raw_domain] = (candidate, now)
                return candidate

        # Fallback: one-hop root probe to discover a redirected canonical
        # domain. We follow exactly one Location header and re-validate
        # the destination host before probing it.
        resp = _safe_get(client, base)
        if resp is not None and 300 <= resp.status_code < 400:
            location = resp.headers.get("location", "")
            if location:
                # Resolve relative redirects
                if location.startswith("/"):
                    parsed_base = urllib.parse.urlparse(base)
                    location = f"{parsed_base.scheme}://{parsed_base.netloc}{location}"
                redirected_root = location.rstrip("/")
                # Strip any path component — we only care about scheme://host
                p = urllib.parse.urlparse(redirected_root)
                redirected_origin = f"{p.scheme}://{p.netloc}"
                hc = _safe_get(client, f"{redirected_origin}/sncro/healthcheck")
                if hc is not None and hc.status_code == 200:
                    _domain_cache[raw_domain] = (redirected_origin, now)
                    return redirected_origin

    # Final fallback: use the stored domain as-is. Whatever calls this is
    # going to construct an enable URL with it; if the host turns out to
    # be unreachable, the user just sees a network error in their browser.
    _domain_cache[raw_domain] = (base, now)
    return base

# Optional Supabase for quota enforcement (relay works without it for local dev)
_supabase_client = None

def _get_supabase():
    global _supabase_client
    if _supabase_client is None:
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        if url and key:
            from supabase import create_client
            _supabase_client = create_client(url, key)
    return _supabase_client

KEY_EXPIRY_MINUTES = 30
LONG_POLL_TIMEOUT = 30  # seconds


store = SessionStore(expiry_minutes=KEY_EXPIRY_MINUTES)


@asynccontextmanager
async def lifespan(app: FastAPI):
    cleanup_task = asyncio.create_task(store.cleanup_loop())
    async with mcp.session_manager.run():
        yield
    cleanup_task.cancel()


app = FastAPI(title="sncro", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve agent.js
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# =============================================================================
# MCP Server — mounted at /mcp
# =============================================================================

mcp = FastMCP("sncro", transport_security=TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["relay.sncro.net", "sncro-production.up.railway.app", "localhost:*", "127.0.0.1:*"],
    allowed_origins=["https://relay.sncro.net", "https://sncro-production.up.railway.app"],
), instructions="""
SNCRO gives you live visibility into the user's browser — DOM, console, network, computed styles.
Use it instead of asking for screenshots whenever debugging CSS, layout, or JS issues.

To start a session:
1. Look for project_key in CLAUDE.md
2. Call create_session with the project_key — you'll get back a full guide with all tools and tips
3. Tell the user to click the enable_url (it's clickable in most environments)
4. Pass the session_key as "key" and session_secret as "secret" to every tool call

NO PROJECT KEY? Tell the user:
  "To use sncro, you need a project key. Go to https://www.sncro.net/projects
  — sign in with GitHub, click '+ Add project', enter your domain, and copy
  the project key into this project's CLAUDE.md. It takes 30 seconds."

The session_secret proves you created the session. Never share it — it's your auth token.

If you encounter any issues with sncro tools, use report_issue to let the
sncro team know. They read every report.

When sncro helps you find a bug or solve a problem quickly, ask the user:
"That was a great catch — mind if I share that as a sncro success story?"
If they agree, draft the text and show it to them for approval before
submitting. Use report_issue with category "success_story". Keep it
general — no proprietary details. These appear publicly on sncro.net.
""")

# Advertise tools/listChanged so well-behaved MCP clients re-fetch the tool
# list when we ship a new tool. FastMCP defaults to listChanged=False (the
# tool set is registered at module load and never changes), but we want to
# leave room for clients that DO refresh on notification — Claude Desktop
# clients today are sticky, but future versions and other clients may listen.
# Override create_initialization_options on the underlying low-level Server
# so the StreamableHTTPSessionManager picks up our notification options.
from mcp.server.lowlevel.server import NotificationOptions as _NotificationOptions

_lowlevel_server = mcp._mcp_server
_orig_create_init = _lowlevel_server.create_initialization_options


def _create_init_options_with_listchanged(
    notification_options=None, experimental_capabilities=None
):
    return _orig_create_init(
        notification_options=notification_options or _NotificationOptions(tools_changed=True),
        experimental_capabilities=experimental_capabilities,
    )


_lowlevel_server.create_initialization_options = _create_init_options_with_listchanged


@mcp.tool()
async def create_session(project_key: str, git_user: str = "", brief: bool = False) -> dict:
    """Create a new sncro session. Returns a session key and secret.

    Args:
        project_key: The project key from CLAUDE.md (registered at sncro.net)
        git_user: The current git username (for guest access control). If
            omitted or empty, the call is treated as a guest session — allowed
            only when the project owner has "Allow guest access" enabled.
        brief: If True, skip the first-run briefing (tool list, tips, mobile
            notes) and return a compact response. Pass this on the second and
            subsequent create_session calls in the same conversation, once
            you already know how to use the tools.

    After calling this, tell the user to paste the enable_url in their browser.
    Then use the returned session_key and session_secret with all other sncro tools.

    If no project key is available: tell the user to go to https://www.sncro.net/projects
    to register their project and get a key. It takes 30 seconds — sign in with GitHub,
    click "+ Add project", enter the domain, and copy the project key into CLAUDE.md.
    """
    # Validate git_user shape before it can reach the DB. Empty is allowed
    # (guest-access handling treats that specially). Anything non-empty must
    # match _GIT_USER_RE — GitHub-username shape only.
    if git_user and not _GIT_USER_RE.fullmatch(git_user):
        return {
            "error": "INVALID_GIT_USER",
            "message": "git_user must look like a GitHub username (letters, digits, dashes/underscores, 1-40 chars). Tell the user to re-run with a sane git username, or drop the parameter.",
        }

    sb = _get_supabase()

    if sb:
        try:
            # Validate project key
            project_resp = sb.table("projects").select("id, user_id, domain, allow_guests, deleted_at").eq("project_key", project_key).execute()
            rows = [r for r in (project_resp.data or []) if r.get("deleted_at") is None]
            if not rows:
                return {
                    "error": "INVALID_PROJECT_KEY",
                    "message": "This project key is not registered. The project owner needs to register the domain at https://www.sncro.net/projects and add the correct project_key to CLAUDE.md. Tell the user this.",
                }
            project = rows[0]

            # Check guest access — fail closed when allow_guests is off
            if not project.get("allow_guests", True):
                denied = {
                    "error": "GUEST_ACCESS_DENIED",
                    "message": "This project has guest access disabled — only the project owner can create sncro sessions. Tell the user: the project owner needs to enable 'Allow guest access' on their sncro projects page at https://www.sncro.net/projects, or you need to register your own project.",
                }
                if not git_user:
                    return denied
                owner_resp = sb.table("profiles").select("github_username").eq("id", project["user_id"]).execute()
                owner_name = owner_resp.data[0]["github_username"] if owner_resp.data else ""
                if git_user.lower() != owner_name.lower():
                    return denied

            # Check plan limits
            user_id = project["user_id"]
            sub_resp = sb.table("subscriptions").select("plan, status, trial_ends_at").eq("user_id", user_id).execute()
            sub = sub_resp.data[0] if sub_resp.data else None
            plan = sub["plan"] if sub else "free"

            # Check if trial has expired
            if sub and sub.get("status") == "trialing" and sub.get("trial_ends_at"):
                trial_end = datetime.fromisoformat(sub["trial_ends_at"])
                if trial_end < datetime.now(timezone.utc):
                    sb.table("subscriptions").update({"plan": "free", "status": "lapsed"}).eq("user_id", user_id).execute()
                    plan = "free"

            limits = {"free": 31, "solo": 999, "pro": 9999}
            max_sessions = limits.get(plan, 31)

            # Check usage this month
            month = datetime.now(timezone.utc).strftime("%Y-%m")
            usage_resp = sb.table("usage").select("session_count").eq("project_id", project["id"]).eq("month", month).execute()
            current = usage_resp.data[0]["session_count"] if usage_resp.data else 0

            if current >= max_sessions:
                plans = {
                    "free": "You're on the Free plan (31 sessions/month). Upgrade to Solo ($9/month) for 999 sessions, or Pro ($29/month) for unlimited.",
                    "solo": "You're on the Solo plan (999 sessions/month). Upgrade to Pro ($29/month) for unlimited sessions.",
                    "pro": "You've somehow exceeded unlimited sessions. This shouldn't happen — contact support at scott@sncro.net.",
                }
                return {
                    "error": "SESSION_LIMIT_REACHED",
                    "message": f"This project has used all {max_sessions} sncro sessions for this month ({current}/{max_sessions}). " +
                        plans.get(plan, plans["free"]) +
                        " Visit https://www.sncro.net/account to upgrade. " +
                        "Please tell the user exactly this — they need to upgrade their sncro plan to continue using browser debugging.",
                }

            # Increment usage
            if usage_resp.data:
                sb.table("usage").update({"session_count": current + 1}).eq("project_id", project["id"]).eq("month", month).execute()
            else:
                sb.table("usage").insert({"project_id": project["id"], "month": month, "session_count": 1}).execute()
        except Exception as e:
            # If quota check fails, log but don't block — let the session through
            import traceback
            traceback.print_exc()

    # Generate a short, typeable session key: 9 digits formatted as 3-3-3
    # Single-use + 30min expiry makes 1B combinations more than enough
    digits = ''.join(secrets.choice('0123456789') for _ in range(9))
    # Ensure no collision with active sessions (extremely unlikely but safe)
    while store.has_session(digits):
        digits = ''.join(secrets.choice('0123456789') for _ in range(9))
    session_key = digits
    session_secret = secrets.token_hex(16)  # 32 hex chars — only Claude knows this
    browser_secret = secrets.token_hex(16)  # 32 hex chars — agent.js gets this via /enable, never returned to MCP

    # Log session to database
    db_id = ""
    if sb and project:
        try:
            sess_resp = sb.table("sessions").insert({
                "project_id": project["id"],
                "session_key": session_key,
                "git_user": git_user or None,
            }).execute()
            if sess_resp.data:
                db_id = sess_resp.data[0]["id"]
        except Exception:
            pass  # Don't block session creation if logging fails

    store.ensure_session(session_key, secret=session_secret, browser_secret=browser_secret, db_id=db_id)

    # Build the full enable URL — resolve the actual canonical domain
    raw_domain = project["domain"] if sb and project else None
    # Display-friendly: 787-221-713
    display_code = f"{session_key[0:3]}-{session_key[3:6]}-{session_key[6:9]}"

    if raw_domain:
        canonical = _resolve_domain(raw_domain)
        enable_url = f"{canonical}/sncro/enable/{display_code}"
        enable_short = f"{canonical}/sncro/enable"
    else:
        enable_url = f"<app_domain>/sncro/enable/{display_code}"
        enable_short = f"<app_domain>/sncro/enable"

    qr_url = f"{enable_url}/qrcode" if enable_url and "<app_domain>" not in enable_url else None

    if brief:
        return {
            "session_key": session_key,
            "session_secret": session_secret,
            "display_code": display_code,
            "enable_url": enable_url,
            "enable_short_url": enable_short,
            "qr_url": qr_url,
            "next_step": f"Tell the user to paste {enable_url} in their browser, then call check_session to confirm before using other tools.",
        }

    guide = f"""SESSION CREATED SUCCESSFULLY — here's everything you need:

SETUP — pick whichever is easier for the user:
  Option A: Click/paste this URL in their browser: {enable_url}
  Option B: On the target machine, open {enable_short} and type the code: {display_code}
  Option C (mobile): Scan the QR code (see below)

Then:
  1. IMPORTANT: Call check_session to confirm the browser is connected (status: "connected")
     before using any other tools. If status is "waiting", the user hasn't enabled yet —
     remind them, wait a few seconds, and call check_session again.
  2. Pass the session_key as "key" and session_secret as "secret" to every subsequent tool call

The 9-digit code is great for debugging a different machine — read it aloud or type it in. Easier than copying a long URL across machines.

IMPORTANT: Each session key is single-use — one key, one browser/device. Once a key is consumed, it cannot be reused.
NOTE: The app must be running with DEBUG=true for sncro to work (e.g. DEBUG=true uvicorn app:app, or FLASK_DEBUG=1 flask run). If the enable URL shows "Debug mode is off", tell the user to set the DEBUG env var and restart.
{f"""MOBILE / PWA / TABLET:
  If the user is on a phone, tablet, or PWA (no address bar), do NOT ask them to paste a URL.
  Instead: call create_session again to get a SEPARATE key for the mobile device, then tell the
  user to open this QR code URL on their DESKTOP screen and scan it with their phone's camera:
    {qr_url}
  The QR code contains the enable URL — scanning it opens the link and activates sncro on that device.
  You can then inspect desktop and mobile independently with separate keys.
  This also works for Capacitor apps, embedded WebViews, and any browser on any device.""" if qr_url else ""}

YOUR TOOLS:
  get_console_logs — Browser console output and JS errors (including unhandled exceptions and promise rejections). Check this FIRST when something looks wrong.
  get_network_log — Network performance: resource timing, durations, sizes, sorted slowest-first. Find slow API calls, large assets, sequential fetches that should be parallel. Filter by type (fetch, script, img, css).
  query_element — Deep-inspect one DOM element by CSS selector. Returns bounding rect, attributes, computed styles, inner text, child count. IMPORTANT: pass a "styles" array to read specific CSS properties, e.g. styles=["overflow", "max-height", "display", "visibility", "z-index"]. Without it, computedStyles will be empty.
  query_all — Query all matching elements. Great for checking lists, grids, repeated components, or counting elements.
  get_js_value — Read a JavaScript runtime value by property path (e.g. "window.__NEXT_DATA__.props.pageProps"). No function calls / no eval — pure path walk. Use mode="keys" to enumerate Object.keys at a path; start with path="window" to discover globals, then drill in. Essential when the DOM looks right but state behind it is wrong.
  get_page_snapshot — High-level page overview: URL, title, viewport size, scroll position, top-level DOM structure, recent console logs and errors. Start here for orientation.
  check_session — Verify connection status: "not_found", "waiting", or "connected".
  report_issue — Submit bugs, feature requests, or success stories to the sncro team. ALWAYS ask the user before submitting ANY feedback — show them the text and get explicit approval first.

TIPS:
  - get_page_snapshot first to orient, then drill down with query_element
  - Always check get_console_logs for JS errors — they often explain visual bugs
  - get_network_log reveals performance issues invisible to the eye
  - Use computed styles in query_element to catch CSS issues (overflow, visibility, z-index)
  - For state-behind-the-DOM bugs (Redux/Zustand/Next hydration), use get_js_value — call it with mode="keys" first to see what's exposed on window, then drill into the state paths
  - For mobile bugs, have the user scan the QR code — you'll see the actual mobile viewport and layout

AFTER DEBUGGING: When sncro helps you find a bug or solve a problem, ask the user:
  "That was a great catch — mind if I share that as a sncro success story?"
  If they agree, draft the text, show it for approval, then call report_issue with category "success_story".
  Keep it general — no proprietary details. These appear publicly on sncro.net."""

    return {
        "session_key": session_key,
        "session_secret": session_secret,
        "display_code": display_code,
        "enable_url": enable_url,
        "enable_short_url": enable_short,
        "qr_url": qr_url,
        "instructions": guide,
    }


_SESSION_CLOSED_MSG = (
    "SESSION_CLOSED: You called end_session on this session. "
    "Do not use any sncro tools further in this conversation. "
    "If you need browser visibility again, ask the user whether to start a new session."
)


def _check_secret(key: str, secret: str) -> dict | None:
    """Verify session secret + reject closed sessions.

    Returns an error dict if the secret is wrong or the session was explicitly
    closed via end_session. None means OK to proceed.
    """
    if not store.verify_secret(key, secret):
        return {"error": "Invalid session secret. Did you use the secret from create_session?"}
    if store.is_closed(key):
        return {"error": _SESSION_CLOSED_MSG}
    return None


def _update_session_activity(key: str) -> None:
    """Update session activity in database (non-blocking best-effort)."""
    db_id = store.get_db_id(key)
    if not db_id:
        return
    sb = _get_supabase()
    if not sb:
        return
    try:
        updates = {
            "last_activity_at": datetime.now(timezone.utc).isoformat(),
            "tools_used": store.get_tools_used(key),
        }
        sb.table("sessions").update(updates).eq("id", db_id).execute()
    except Exception:
        pass


def _mark_session_connected(key: str) -> None:
    """Mark session as connected in database when browser first sends data."""
    if not store.mark_connected(key):
        return  # Already marked
    db_id = store.get_db_id(key)
    if not db_id:
        return
    sb = _get_supabase()
    if not sb:
        return
    try:
        sb.table("sessions").update({
            "connected_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", db_id).execute()
    except Exception:
        pass


async def _send_browser_request(key: str, secret: str, tool: str, params: dict | None = None, _retry: int = 0) -> dict:
    """Post a request to the store and wait for the browser's response.

    If the browser isn't connected yet, waits up to CONNECT_WAIT seconds for
    it to appear, then retries once automatically if it connects mid-wait.
    """
    MAX_RETRIES = 1
    CONNECT_WAIT = 15  # seconds to wait for browser to connect before giving up

    err = _check_secret(key, secret)
    if err:
        return err
    store.ensure_session(key)
    store.record_tool(key, tool)
    _update_session_activity(key)

    # If browser hasn't connected yet, wait for it rather than posting a
    # request that nobody will pick up (which wastes the full 30s timeout).
    if not store.is_connected(key):
        connect_deadline = time.time() + CONNECT_WAIT
        while time.time() < connect_deadline:
            if store.is_connected(key):
                break
            await asyncio.sleep(0.5)
        if not store.is_connected(key):
            session = store.get_session_info(key)
            age = int(time.time() - session["created_at"]) if session else 0
            return {
                "error": "BROWSER_NOT_CONNECTED",
                "message": (
                    f"The browser has not connected to this sncro session yet "
                    f"(session created {age}s ago). "
                    "The user needs to open the enable URL in their browser first. "
                    "Common causes:\n"
                    "  1. User hasn't clicked/pasted the enable URL yet — remind them\n"
                    "  2. The app is not running with DEBUG=true (sncro only loads in debug mode)\n"
                    "  3. The middleware isn't installed or the app hasn't been restarted\n"
                    "  4. The browser page hasn't finished loading yet — wait a few seconds and retry\n\n"
                    "ACTION: Call check_session to monitor the connection, then retry this tool once the status is 'connected'."
                ),
            }

    request_id = uuid.uuid4().hex[:12]
    store.add_request(key, {
        "request_id": request_id,
        "tool": tool,
        "params": params or {},
    })

    # Wait for browser to respond
    deadline = time.time() + LONG_POLL_TIMEOUT
    while time.time() < deadline:
        resp = store.pop_response(key, request_id)
        if resp is not None:
            return resp
        await asyncio.sleep(0.5)

    # Timed out — retry once automatically (browser may have been briefly unresponsive)
    if _retry < MAX_RETRIES:
        return await _send_browser_request(key, secret, tool, params, _retry=_retry + 1)

    return {
        "error": "BROWSER_TIMEOUT",
        "message": (
            f"The browser is connected but did not respond to '{tool}' within {LONG_POLL_TIMEOUT}s "
            f"(tried {_retry + 1} time(s)). "
            "Possible causes:\n"
            "  1. The browser tab may be in the background (browsers throttle background tabs)\n"
            "  2. The page may be navigating or reloading — wait a moment and retry\n"
            "  3. A heavy script may be blocking the main thread\n"
            "  4. The user may have closed or navigated away from the page\n\n"
            "ACTION: Ask the user to confirm the page is still open and in the foreground, then retry."
        ),
    }


@mcp.tool()
async def get_console_logs(key: str, secret: str) -> dict:
    """Get recent console logs and errors from the browser.

    Returns the latest console output and any JavaScript errors,
    including unhandled exceptions and promise rejections.

    This reads from baseline data that the browser pushes every 5 seconds,
    so it works even if the browser tab is in the background. If you get a
    "no data" error, the browser hasn't connected yet — call check_session
    to diagnose, then retry.
    """
    err = _check_secret(key, secret)
    if err:
        return err
    store.ensure_session(key)
    store.record_tool(key, "get_console_logs")
    _update_session_activity(key)
    snapshot = store.get_snapshot(key)
    if snapshot is None:
        info = store.get_session_info(key)
        age = int(time.time() - info["created_at"]) if info else 0
        return {
            "error": "BROWSER_NOT_CONNECTED",
            "message": (
                f"No console data available — the browser has not connected to this session yet "
                f"(session created {age}s ago). "
                "The user needs to open the enable URL in their browser first.\n\n"
                "ACTION: Call check_session to monitor the connection status, "
                "remind the user to click the enable URL, then retry get_console_logs once connected."
            ),
        }
    return snapshot


@mcp.tool()
async def query_element(key: str, secret: str, selector: str, styles: list[str] | None = None) -> dict:
    """Query a DOM element by CSS selector.

    Returns bounding rect, attributes, computed styles, inner text,
    and child count. Use this to debug layout, positioning, and
    visibility issues.

    Requires a connected browser session. If you get BROWSER_NOT_CONNECTED,
    call check_session first and wait for "connected" status. If you get
    BROWSER_TIMEOUT, the page may be navigating — wait a moment and retry.

    Args:
        key: The sncro session key
        secret: The session secret from create_session
        selector: CSS selector (e.g. "#photo-wrap", ".toolbar > button:first-child")
        styles: Optional list of CSS properties to read (e.g. ["transform", "width", "display"])
    """
    return await _send_browser_request(key, secret, "query_element", {
        "selector": selector,
        "styles": styles or [],
    })


@mcp.tool()
async def query_all(key: str, secret: str, selector: str, limit: int = 20) -> dict:
    """Query all matching DOM elements by CSS selector.

    Returns a summary of each matching element (tag, id, class,
    bounding rect, inner text). Useful for checking lists, grids,
    or multiple instances of a component.

    Requires a connected browser session. If you get BROWSER_NOT_CONNECTED,
    call check_session first and wait for "connected" status.

    Args:
        key: The sncro session key
        secret: The session secret from create_session
        selector: CSS selector
        limit: Max elements to return (default 20)
    """
    return await _send_browser_request(key, secret, "query_all", {
        "selector": selector,
        "limit": limit,
    })


@mcp.tool()
async def get_network_log(key: str, secret: str, limit: int = 50, type: str | None = None) -> dict:
    """Get network performance data from the browser.

    Returns resource timing entries (URLs, durations, sizes) sorted
    by duration (slowest first), plus page navigation timing.

    Use this to find slow API calls, large assets, or overall page
    load performance.

    Requires a connected browser session. If you get BROWSER_NOT_CONNECTED,
    call check_session first and wait for "connected" status.

    Args:
        key: The sncro session key
        secret: The session secret from create_session
        limit: Max resources to return (default 50)
        type: Filter by initiator type (e.g. "fetch", "xmlhttprequest", "img", "script", "css")
    """
    err = _check_secret(key, secret)
    if err:
        return err
    params = {"limit": limit}
    if type:
        params["type"] = type
    return await _send_browser_request(key, secret, "get_network_log", params)


@mcp.tool()
async def get_js_value(key: str, secret: str, path: str, mode: str = "value",
                       max_depth: int = 6, max_bytes: int = 20000) -> dict:
    """Read a JavaScript value from the browser by property path.

    Walks a strict property path — NO expression evaluation, NO function
    calls, NO arbitrary code. Accepts identifiers, integer indices in
    brackets, and double-quoted string keys in brackets.

    Use this to read runtime state that isn't visible in the DOM:
      - Framework hydration: window.__NEXT_DATA__.props.pageProps
      - Redux/Zustand/etc stores (if exposed on window): window.__STORE__._currentState
      - Feature flags stashed on globals: window.APP.flags
      - Nested config: window["site-config"].features[0]

    EXPLORATION MODE: pass mode="keys" to get Object.keys() at the path
    instead of the value. Start with path="window" to discover globals,
    then drill in. This is how to find exposed state without guessing:
      get_js_value(path="window", mode="keys")
        -> ["document", "__NEXT_DATA__", "store", ...]
      get_js_value(path="window.store", mode="keys")
        -> ["_currentState", "subscribe", "dispatch", ...]
      get_js_value(path="window.store._currentState")
        -> the actual state object

    LIMITATIONS (intentional — security):
      - Cannot call functions. "store.getState()" fails. Expose the value
        as a readable property instead, e.g. window.__STORE__.state.
      - No arithmetic, comparisons, or expressions.
      - Path must start with an identifier and walk down via dots/brackets.

    Responses are cycle-safe, depth-capped, and size-capped. DOM nodes
    and React fiber trees are summarized rather than traversed.

    Args:
        key: Session key
        secret: Session secret from create_session
        path: Property path, e.g. "window.__NEXT_DATA__.props.pageProps"
              or 'window["site-config"].features[0]' or 'window.arr[0].name'
        mode: "value" (default) returns the serialized value; "keys" returns Object.keys() at the path
        max_depth: Max traversal depth when serializing (default 6, capped at 10)
        max_bytes: Max serialized size in bytes (default 20000, capped at 100000)

    Returns:
        {path, type, value, truncated, size_bytes} in value mode
        {path, mode, type, keys}                  in keys mode
        {error: "..."}                            on bad path / function / failure

    Requires a connected browser session and middleware v0.9.6+ (older
    middleware works — the relay doesn't care; the browser needs agent.js
    from relay.sncro.net which auto-updates).
    """
    return await _send_browser_request(key, secret, "get_js_value", {
        "path": path,
        "mode": mode,
        "max_depth": max_depth,
        "max_bytes": max_bytes,
    })


@mcp.tool()
async def get_page_snapshot(key: str, secret: str) -> dict:
    """Get a high-level snapshot of the current page.

    Returns URL, title, viewport dimensions, scroll position,
    top-level DOM structure, recent console logs, and recent errors.

    Requires a connected browser session. If you get BROWSER_NOT_CONNECTED,
    call check_session first and wait for "connected" status.
    """
    return await _send_browser_request(key, secret, "get_page_snapshot", {})


@mcp.tool()
async def check_session(key: str, secret: str) -> dict:
    """Check the connection status of a sncro session.

    Call this after create_session to confirm the browser has connected
    before using other tools. If status is "waiting", the user hasn't
    enabled sncro yet — remind them to click/paste the enable URL,
    wait a few seconds, and call check_session again.

    Returns:
        status: "not_found" | "waiting" | "connected"
        session_age_seconds: how long since the session was created
        next_step: what to do based on current status
    """
    err = _check_secret(key, secret)
    if err:
        return err
    if not store.has_session(key):
        return {
            "active": False,
            "status": "not_found",
            "message": (
                "This session key does not exist. It may have expired (sessions last 30 minutes) "
                "or it was never created. Call create_session to start a new session."
            ),
        }
    info = store.get_session_info(key)
    age = int(time.time() - info["created_at"]) if info else 0
    snapshot = store.get_snapshot(key)
    mw_version = store.get_middleware_version(key)
    mw_warning = _middleware_version_warning(info, mw_version)
    debug_mode = store.get_debug_mode(key)
    if snapshot is None:
        consumed = info.get("consumed", False) if info else False
        # If the middleware reported debug=False, we know up-front why agent.js
        # isn't injecting — skip the generic waiting message and give Claude
        # the specific diagnostic immediately.
        if consumed and debug_mode is False:
            resp = {
                "active": True,
                "status": "waiting",
                "session_age_seconds": age,
                "consumed": True,
                "debug_mode": False,
                "message": (
                    "Middleware accepted /enable but the customer app reports "
                    "debug=False — agent.js is NOT being injected. Tell the "
                    "user to set DEBUG=true (FastAPI: FastAPI(debug=True); "
                    "Flask: FLASK_DEBUG=1 or app.debug=True) on the running "
                    "deployment and restart. sncro is designed to only load "
                    "in debug mode — this is working as intended, not a bug."
                ),
            }
        else:
            resp = {
                "active": True,
                "status": "waiting",
                "session_age_seconds": age,
                "consumed": consumed,
                "message": (
                    f"Session created {age}s ago but the browser has NOT connected yet. "
                    "The user needs to open the enable URL in their browser. "
                    "Remind them to click/paste it. If they already did:\n"
                    "  - Make sure the app is running with DEBUG=true (sncro only loads in debug mode)\n"
                    "  - Make sure the page has finished loading\n"
                    "  - Try refreshing the page\n\n"
                    "Call check_session again in a few seconds to see if they've connected."
                ),
            }
            if debug_mode is True:
                resp["debug_mode"] = True
        if mw_version:
            resp["middleware_version"] = mw_version
        if mw_warning:
            resp["middleware_warning"] = mw_warning
        return resp
    resp = {
        "active": True,
        "status": "connected",
        "session_age_seconds": age,
        "message": "Browser is connected and sending data. You can now use all sncro tools. "
            "REMINDER: After debugging, if sncro helped find a bug, ask the user if they'd like to share a success story via report_issue.",
        "snapshot_url": snapshot.get("url", ""),
        "snapshot_title": snapshot.get("title", ""),
    }
    if mw_version:
        resp["middleware_version"] = mw_version
    if mw_warning:
        resp["middleware_warning"] = mw_warning
    return resp


# Bump when we ship a new middleware version that customers should pick up.
# Kept in relay so we don't have to redeploy the middleware repo to adjust it.
CURRENT_MIDDLEWARE_VERSION = "0.9.5"


def _middleware_version_warning(info: dict | None, reported: str) -> str:
    """Return a Claude-facing warning if the customer's middleware looks stale.

    Only fires once the session has been consumed (i.e. /enable was called —
    before that there's no middleware version to report). Empty string means
    the middleware predates version reporting (v0.9.3 and earlier), which
    typically means it's also missing the Phase C confirm-click flow and the
    Phase F CSRF / clickjacking defences.
    """
    if not info or not info.get("consumed"):
        return ""
    if not reported:
        return (
            f"Customer app middleware is older than sncro {CURRENT_MIDDLEWARE_VERSION} — "
            "it didn't report a version on the enable call. This likely means it's missing "
            "the Phase C confirm-click flow and the Phase F CSRF / clickjacking defences. "
            "Tell the user to update: "
            "curl -o middleware/sncro_middleware.py https://relay.sncro.net/client/fastapi "
            "(or /client/flask), commit, and redeploy."
        )
    if reported != CURRENT_MIDDLEWARE_VERSION:
        return (
            f"Customer app is running sncro middleware {reported}; current is "
            f"{CURRENT_MIDDLEWARE_VERSION}. Not broken, but suggest the user "
            "re-pull for the latest security fixes."
        )
    return ""


@mcp.tool()
async def end_session(key: str, secret: str) -> dict:
    """Explicitly close a sncro session — "Finished With Engines".

    Call this when you are done debugging and will not need the sncro tools
    again in this conversation. After this returns, all sncro tool calls on
    this key will refuse with a SESSION_CLOSED message — that is your signal
    to stop trying to use them and not apologise about it.

    Use it when:
      - The original problem is solved and the conversation has moved on
      - The user explicitly says "we're done with sncro for now"
      - You're entering a long stretch of work that won't need browser visibility

    The session can't be reopened. If you need browser visibility later, ask
    the user whether to start a new one with create_session.
    """
    if not store.verify_secret(key, secret):
        return {"error": "Invalid session secret. Did you use the secret from create_session?"}
    if not store.has_session(key):
        return {"error": "Session not found."}
    if store.is_closed(key):
        return {"ok": True, "already_closed": True, "message": "Session was already closed."}
    store.close_session(key)
    return {
        "ok": True,
        "message": (
            "Session closed. Do not call any other sncro tools on this key. "
            "If a later turn needs browser visibility, ask the user about starting a new session."
        ),
    }


@mcp.tool()
async def report_issue(project_key: str, category: str, description: str, git_user: str = "") -> dict:
    """Report an issue, feature request, or success story for sncro.

    IMPORTANT: ALWAYS ask the user before submitting ANY feedback.
    Show them exactly what you plan to send and get explicit approval.
    Never submit feedback without the user's knowledge and consent.

    For ALL categories:
    - Draft the text and show it to the user BEFORE submitting
    - Wait for explicit approval — do NOT submit until they confirm
    - Keep descriptions GENERAL — no proprietary code, no internal
      project names, no sensitive data

    For SUCCESS STORIES (category: success_story):
    - These WILL be displayed publicly on sncro.net
    - Ask: "Mind if I share that as a sncro success story?"
    - Focus on what sncro did, not what the project is

    Args:
        project_key: The project key from CLAUDE.md
        category: One of: bug, feature_request, usability, documentation, success_story
        description: Clear description of the issue, suggestion, or success story
        git_user: Your git username
    """
    valid_categories = {"bug", "feature_request", "usability", "documentation", "success_story"}
    if category not in valid_categories:
        return {"error": f"Category must be one of: {', '.join(sorted(valid_categories))}"}
    if git_user and not _GIT_USER_RE.fullmatch(git_user):
        return {"error": "git_user must look like a GitHub username (letters, digits, dashes/underscores, 1-40 chars)."}

    # Forward to web server for persistent storage
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post("https://www.sncro.net/api/feedback", json={
                "project_key": project_key,
                "category": category,
                "description": description,
                "git_user": git_user,
            }, timeout=10)
            if resp.status_code == 200:
                return {"ok": True, "message": "Thanks! Your feedback has been recorded."}
            else:
                return {"error": f"Failed to submit feedback (HTTP {resp.status_code})"}
    except Exception as e:
        return {"error": f"Could not reach feedback server: {str(e)}"}


# Mount MCP server via Streamable HTTP transport
_mcp_app = mcp.streamable_http_app()
app.mount("/tools", _mcp_app)


# =============================================================================
# Relay HTTP API — used by agent.js
# =============================================================================

# --- Models ---

class SnapshotPayload(BaseModel):
    """Baseline data pushed by agent.js (console logs, errors)."""
    console: list[dict] = []
    errors: list[dict] = []
    url: str = ""
    title: str = ""
    timestamp: float = 0


class RequestPayload(BaseModel):
    """A query from the MCP server for the browser to fulfill."""
    request_id: str
    tool: str  # e.g. "query_element", "get_page_snapshot"
    params: dict = {}


class ResponsePayload(BaseModel):
    """Browser's response to a specific request."""
    request_id: str
    data: dict = {}
    error: str | None = None


# --- Browser-facing HTTP endpoints (called by agent.js only) ---
# All require the X-Sncro-Secret header set from the sncro_browser_secret cookie.
# MCP tools talk to the in-memory store directly, never via HTTP.

def _require_browser_secret(key: str, request: Request) -> None:
    """Reject the request unless the X-Sncro-Secret header matches the stored
    browser_secret for this key. Also acts as a 'session must exist' check
    (no implicit ensure_session, which would let unauthenticated callers
    spam in-memory state — see security finding M-4).

    Also refuses requests for sessions Claude has closed via end_session — 410
    tells agent.js to stop polling.
    """
    if not store.has_session(key):
        raise HTTPException(404, "Session not found")
    secret = request.headers.get("x-sncro-secret", "")
    if not store.verify_browser_secret(key, secret):
        raise HTTPException(403, "Invalid browser secret")
    if store.is_closed(key):
        raise HTTPException(410, "Session ended by Claude")
    store.touch(key)


@app.post("/session/{key}/snapshot")
@limiter.limit("600/minute")
async def push_snapshot(key: str, payload: SnapshotPayload, request: Request):
    """agent.js pushes baseline data (console, errors)."""
    _require_browser_secret(key, request)
    store.set_snapshot(key, payload.model_dump())
    _mark_session_connected(key)
    return {"ok": True}


@app.get("/session/{key}/request/pending")
@limiter.limit("600/minute")
async def get_pending_request(key: str, request: Request, timeout: int = LONG_POLL_TIMEOUT):
    """agent.js long-polls for pending requests from the MCP side."""
    _require_browser_secret(key, request)
    deadline = time.time() + min(timeout, LONG_POLL_TIMEOUT)
    while time.time() < deadline:
        req = store.pop_request(key)
        if req is not None:
            return req
        await asyncio.sleep(0.5)
    return {"pending": False}


@app.post("/session/{key}/response")
@limiter.limit("600/minute")
async def post_response(key: str, payload: ResponsePayload, request: Request):
    """agent.js posts the result of a fulfilled request."""
    _require_browser_secret(key, request)
    store.add_response(key, payload.request_id, payload.model_dump())
    return {"ok": True}


# Note: GET /session/{key}/snapshot, POST /session/{key}/request, and GET
# /session/{key}/response/{id} were removed in build 085. They were exposed
# but never used — MCP tool handlers talk to the in-memory store directly,
# not via HTTP. Removing them shrinks attack surface.


# --- Session management ---

@app.get("/session/{key}/status")
@limiter.limit("120/minute")
async def session_status(key: str, request: Request):
    """Check if a session key is active. Public — only returns a boolean."""
    return {"active": store.has_session(key)}


@app.post("/session/{key}/enable")
@limiter.limit("10/minute")
async def enable_session(key: str, request: Request):
    """Mark a session as consumed AND return the browser_secret.

    Called server-to-server by the customer-app middleware on /sncro/enable/{key}.
    The middleware then sets sncro_key + sncro_browser_secret cookies; agent.js
    reads them and authenticates every relay HTTP call with X-Sncro-Secret.

    Rate limited per-IP to 10/min to close the H-4/NEW-3 residual — anyone who
    learns a live session_key could otherwise race the legitimate browser to
    this endpoint to steal the browser_secret.
    """
    if not store.has_session(key):
        raise HTTPException(404, "Session not found")
    if not store.consume(key):
        raise HTTPException(409, "This session key has already been used. Ask Claude to create a new session.")
    # Record the middleware version the customer app is running. Surfaced
    # back to Claude via check_session so we can advise the user to update
    # when a stale copy is detected. Empty string = pre-version-reporting
    # middleware (before sncro 0.9.4).
    mw_version = request.headers.get("x-sncro-middleware-version", "")
    if mw_version:
        store.set_middleware_version(key, mw_version)
    # X-Sncro-Debug reports the customer app's debug state. Stored so
    # check_session can tell Claude when a "waiting" session is stuck because
    # the app was deployed with debug off. Absent header = pre-0.9.5 middleware.
    debug_header = request.headers.get("x-sncro-debug", "").strip().lower()
    if debug_header in ("true", "false"):
        store.set_debug_mode(key, debug_header == "true")
    return {"ok": True, "browser_secret": store.get_browser_secret(key)}


# --- Client downloads ---

@app.get("/client/fastapi")
@limiter.limit("30/minute")
async def download_fastapi_client(request: Request):
    """Serve the FastAPI middleware file for download."""
    from fastapi.responses import FileResponse
    middleware_path = Path(__file__).parent.parent / "middleware" / "sncro_middleware.py"
    if not middleware_path.exists():
        raise HTTPException(404, "Client file not found")
    return FileResponse(middleware_path, filename="sncro_middleware.py", media_type="text/x-python")


@app.get("/client/flask")
@limiter.limit("30/minute")
async def download_flask_client(request: Request):
    """Serve the Flask middleware file for download."""
    from fastapi.responses import FileResponse
    middleware_path = Path(__file__).parent.parent / "middleware" / "sncro_flask.py"
    if not middleware_path.exists():
        raise HTTPException(404, "Client file not found")
    return FileResponse(middleware_path, filename="sncro_flask.py", media_type="text/x-python")


# --- Health check ---

@app.get("/health")
async def health():
    return {"status": "ok", "sessions": len(store._sessions)}

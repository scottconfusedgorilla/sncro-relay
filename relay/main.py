"""sncro relay — keyed long-poll rendezvous server + MCP server."""

import asyncio
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from mcp.server.transport_security import TransportSecuritySettings

from relay.store import SessionStore

# Cache resolved domains for 5 minutes
_domain_cache: dict[str, tuple[str, float]] = {}
DOMAIN_CACHE_TTL = 300  # seconds


def _resolve_domain(raw_domain: str) -> str:
    """Probe the middleware healthcheck to find the canonical domain.
    Follows redirects to handle www/non-www, vanity domains, etc."""
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

    try:
        with httpx.Client(follow_redirects=True, timeout=5) as client:
            for candidate in candidates:
                try:
                    resp = client.get(f"{candidate}/sncro/healthcheck")
                    if resp.status_code == 200:
                        final_url = str(resp.url)
                        resolved = final_url.rsplit("/sncro/healthcheck", 1)[0]
                        _domain_cache[raw_domain] = (resolved, now)
                        return resolved
                except Exception:
                    continue
    except Exception:
        pass

    # Fallback: follow root redirect to discover the actual domain
    try:
        with httpx.Client(follow_redirects=True, timeout=5) as client:
            resp = client.get(base)
            if resp.status_code == 200:
                final_url = str(resp.url).rstrip("/")
                # Check if the redirected domain has the healthcheck
                try:
                    hc = client.get(f"{final_url}/sncro/healthcheck")
                    if hc.status_code == 200:
                        resolved = str(hc.url).rsplit("/sncro/healthcheck", 1)[0]
                        _domain_cache[raw_domain] = (resolved, now)
                        return resolved
                except Exception:
                    pass
    except Exception:
        pass

    # Final fallback: use the stored domain as-is
    resolved = base
    _domain_cache[raw_domain] = (resolved, now)
    return resolved

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
  "To use sncro, you need a project key. Go to https://www.sncro.net/dashboard
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


@mcp.tool()
async def create_session(project_key: str, git_user: str = "") -> dict:
    """Create a new sncro session. Returns a session key and secret.

    Args:
        project_key: The project key from CLAUDE.md (registered at sncro.net)
        git_user: The current git username (for guest access control)

    After calling this, tell the user to paste the enable_url in their browser.
    Then use the returned session_key and session_secret with all other sncro tools.

    If no project key is available: tell the user to go to https://www.sncro.net/dashboard
    to register their project and get a key. It takes 30 seconds — sign in with GitHub,
    click "+ Add project", enter the domain, and copy the project key into CLAUDE.md.
    """
    sb = _get_supabase()

    if sb:
        try:
            # Validate project key
            project_resp = sb.table("projects").select("id, user_id, domain, allow_guests, deleted_at").eq("project_key", project_key).execute()
            rows = [r for r in (project_resp.data or []) if r.get("deleted_at") is None]
            if not rows:
                return {
                    "error": "INVALID_PROJECT_KEY",
                    "message": "This project key is not registered. The project owner needs to register the domain at https://www.sncro.net/dashboard and add the correct project_key to CLAUDE.md. Tell the user this.",
                }
            project = rows[0]

            # Check guest access
            if not project.get("allow_guests", True) and git_user:
                owner_resp = sb.table("profiles").select("github_username").eq("id", project["user_id"]).execute()
                owner_name = owner_resp.data[0]["github_username"] if owner_resp.data else ""
                if git_user.lower() != owner_name.lower():
                    return {
                        "error": "GUEST_ACCESS_DENIED",
                        "message": "This project has guest access disabled — only the project owner can create sncro sessions. Tell the user: the project owner needs to enable 'Allow guest access' in their sncro dashboard at https://www.sncro.net/dashboard, or you need to register your own project.",
                    }

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

    store.ensure_session(session_key, secret=session_secret, db_id=db_id)

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
  get_page_snapshot — High-level page overview: URL, title, viewport size, scroll position, top-level DOM structure, recent console logs and errors. Start here for orientation.
  check_session — Verify connection status: "not_found", "waiting", or "connected".
  report_issue — Submit bugs, feature requests, or success stories to the sncro team. ALWAYS ask the user before submitting ANY feedback — show them the text and get explicit approval first.

TIPS:
  - get_page_snapshot first to orient, then drill down with query_element
  - Always check get_console_logs for JS errors — they often explain visual bugs
  - get_network_log reveals performance issues invisible to the eye
  - Use computed styles in query_element to catch CSS issues (overflow, visibility, z-index)
  - For mobile bugs, have the user scan the QR code — you'll see the actual mobile viewport and layout"""

    return {
        "session_key": session_key,
        "session_secret": session_secret,
        "display_code": display_code,
        "enable_url": enable_url,
        "enable_short_url": enable_short,
        "qr_url": qr_url,
        "instructions": guide,
    }


def _check_secret(key: str, secret: str) -> dict | None:
    """Verify session secret. Returns error dict if invalid, None if OK."""
    if not store.verify_secret(key, secret):
        return {"error": "Invalid session secret. Did you use the secret from create_session?"}
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
    if snapshot is None:
        return {
            "active": True,
            "status": "waiting",
            "session_age_seconds": age,
            "consumed": info.get("consumed", False) if info else False,
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
    return {
        "active": True,
        "status": "connected",
        "session_age_seconds": age,
        "message": "Browser is connected and sending data. You can now use all sncro tools.",
        "snapshot_url": snapshot.get("url", ""),
        "snapshot_title": snapshot.get("title", ""),
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


# --- Snapshot endpoints (baseline, one-way) ---

@app.post("/session/{key}/snapshot")
async def push_snapshot(key: str, payload: SnapshotPayload):
    """agent.js pushes baseline data (console, errors)."""
    store.ensure_session(key)
    store.set_snapshot(key, payload.model_dump())
    _mark_session_connected(key)
    return {"ok": True}


@app.get("/session/{key}/snapshot")
async def get_snapshot(key: str):
    """MCP server reads latest baseline data."""
    store.ensure_session(key)
    snapshot = store.get_snapshot(key)
    if snapshot is None:
        raise HTTPException(404, "No snapshot yet")
    return snapshot


# --- Request/response endpoints (two-way, long-poll) ---

@app.post("/session/{key}/request")
async def post_request(key: str, payload: RequestPayload):
    """MCP server posts a query for the browser to fulfill."""
    store.ensure_session(key)
    store.add_request(key, payload.model_dump())
    return {"ok": True, "request_id": payload.request_id}


@app.get("/session/{key}/request/pending")
async def get_pending_request(key: str, timeout: int = LONG_POLL_TIMEOUT):
    """agent.js long-polls for pending requests."""
    store.ensure_session(key)
    deadline = time.time() + min(timeout, LONG_POLL_TIMEOUT)
    while time.time() < deadline:
        req = store.pop_request(key)
        if req is not None:
            return req
        await asyncio.sleep(0.5)
    return {"pending": False}


@app.post("/session/{key}/response")
async def post_response(key: str, payload: ResponsePayload):
    """agent.js posts the result of a fulfilled request."""
    store.ensure_session(key)
    store.add_response(key, payload.request_id, payload.model_dump())
    return {"ok": True}


@app.get("/session/{key}/response/{request_id}")
async def get_response(key: str, request_id: str, timeout: int = LONG_POLL_TIMEOUT):
    """MCP server long-polls for a specific request's response."""
    store.ensure_session(key)
    deadline = time.time() + min(timeout, LONG_POLL_TIMEOUT)
    while time.time() < deadline:
        resp = store.pop_response(key, request_id)
        if resp is not None:
            return resp
        await asyncio.sleep(0.5)
    raise HTTPException(408, "Timeout waiting for browser response")


# --- Session management ---

@app.get("/session/{key}/status")
async def session_status(key: str):
    """Check if a session key is active."""
    return {"active": store.has_session(key)}


@app.post("/session/{key}/consume")
async def consume_session(key: str):
    """Mark a session key as consumed (bound to one browser). Returns error if already consumed."""
    if not store.has_session(key):
        raise HTTPException(404, "Session not found")
    if not store.consume(key):
        raise HTTPException(409, "This session key has already been used. Ask Claude to create a new session.")
    return {"ok": True}


# --- Client downloads ---

@app.get("/client/fastapi")
async def download_fastapi_client():
    """Serve the FastAPI middleware file for download."""
    from fastapi.responses import FileResponse
    middleware_path = Path(__file__).parent.parent / "middleware" / "sncro_middleware.py"
    if not middleware_path.exists():
        raise HTTPException(404, "Client file not found")
    return FileResponse(middleware_path, filename="sncro_middleware.py", media_type="text/x-python")


@app.get("/client/flask")
async def download_flask_client():
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

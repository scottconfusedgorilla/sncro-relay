"""sncro relay — keyed long-poll rendezvous server + MCP server."""

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from relay.store import SessionStore

KEY_EXPIRY_HOURS = 4
LONG_POLL_TIMEOUT = 30  # seconds


store = SessionStore(expiry_hours=KEY_EXPIRY_HOURS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    cleanup_task = asyncio.create_task(store.cleanup_loop())
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

mcp = FastMCP("sncro", instructions="""
SNCRO gives you live visibility into the user's browser.
Use get_console_logs to check for errors and debug output.
Use query_element to inspect specific DOM elements (bounding rects, styles, attributes).
Use get_page_snapshot for a high-level page overview.
The user will give you a session key — pass it to every tool call.
""")


async def _send_browser_request(key: str, tool: str, params: dict | None = None) -> dict:
    """Post a request to the store and wait for the browser's response."""
    store.ensure_session(key)
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
    return {"error": "Browser did not respond in time. Is the page open with sncro enabled?"}


@mcp.tool()
async def get_console_logs(key: str) -> dict:
    """Get recent console logs and errors from the browser.

    Returns the latest console output and any JavaScript errors,
    including unhandled exceptions and promise rejections.
    """
    store.ensure_session(key)
    snapshot = store.get_snapshot(key)
    if snapshot is None:
        return {"error": "No data yet. Is the browser page open with sncro enabled?"}
    return snapshot


@mcp.tool()
async def query_element(key: str, selector: str, styles: list[str] | None = None) -> dict:
    """Query a DOM element by CSS selector.

    Returns bounding rect, attributes, computed styles, inner text,
    and child count. Use this to debug layout, positioning, and
    visibility issues.

    Args:
        key: The sncro session key
        selector: CSS selector (e.g. "#photo-wrap", ".toolbar > button:first-child")
        styles: Optional list of CSS properties to read (e.g. ["transform", "width", "display"])
    """
    return await _send_browser_request(key, "query_element", {
        "selector": selector,
        "styles": styles or [],
    })


@mcp.tool()
async def query_all(key: str, selector: str, limit: int = 20) -> dict:
    """Query all matching DOM elements by CSS selector.

    Returns a summary of each matching element (tag, id, class,
    bounding rect, inner text). Useful for checking lists, grids,
    or multiple instances of a component.

    Args:
        key: The sncro session key
        selector: CSS selector
        limit: Max elements to return (default 20)
    """
    return await _send_browser_request(key, "query_all", {
        "selector": selector,
        "limit": limit,
    })


@mcp.tool()
async def get_page_snapshot(key: str) -> dict:
    """Get a high-level snapshot of the current page.

    Returns URL, title, viewport dimensions, scroll position,
    top-level DOM structure, recent console logs, and recent errors.
    """
    return await _send_browser_request(key, "get_page_snapshot", {})


@mcp.tool()
async def check_session(key: str) -> dict:
    """Check if a sncro session is active.

    Use this to verify the browser has sncro enabled before
    making other queries.
    """
    return {"active": store.has_session(key)}


# Mount MCP server via SSE transport
app.mount("/mcp", mcp.sse_app())


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


# --- Health check ---

@app.get("/health")
async def health():
    return {"status": "ok", "sessions": len(store._sessions)}

"""sncro relay — keyed long-poll rendezvous server."""

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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


app = FastAPI(title="sncro relay", lifespan=lifespan)
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

"""try.sncro.net — a deliberately broken page for demoing sncro."""

from datetime import date, timedelta

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

app = FastAPI(debug=False)  # TESTING: prove sncro vanishes in production

if app.debug:
    from middleware.sncro_middleware import SncroMiddleware, sncro_routes
    app.include_router(sncro_routes)
    app.add_middleware(SncroMiddleware, relay_url="https://relay.sncro.net")

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


# --- Intentionally buggy sports dashboard ---

SPORTS_API = "https://www.thesportsdb.com/api/v1/json/3"


async def fetch_scores():
    """Fetch recent sports events. Intentional bug: no timeout, no error handling."""
    async with httpx.AsyncClient() as client:
        # Bug 1: Fetches sequentially instead of in parallel
        # Each of these is a separate HTTP round-trip that could run concurrently
        r1 = await client.get(f"{SPORTS_API}/eventspastleague.php?id=4328")  # EPL
        r2 = await client.get(f"{SPORTS_API}/eventspastleague.php?id=4387")  # NBA
        r3 = await client.get(f"{SPORTS_API}/eventspastleague.php?id=4380")  # NHL
        r4 = await client.get(f"{SPORTS_API}/eventspastleague.php?id=4424")  # MLB

        events = []
        for resp in [r1, r2, r3, r4]:
            if resp.status_code == 200:
                data = resp.json()
                events.extend(data.get("events") or [])
        return events[:15]  # Cap at 15 for display


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    try:
        events = await fetch_scores()
    except Exception:
        events = []

    # Bug 2: Pass raw data without sanitizing — some fields may be None
    return templates.TemplateResponse(request, "index.html", {
        "events": events,
    })


@app.get("/api/scores")
async def api_scores():
    """API endpoint that's intentionally slow — fetches sequentially."""
    try:
        events = await fetch_scores()
        return {"events": events, "count": len(events)}
    except Exception as e:
        return {"error": str(e), "events": []}

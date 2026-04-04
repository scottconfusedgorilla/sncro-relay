"""try.sncro.net — a deliberately broken page for demoing sncro."""

from datetime import date, timedelta

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from middleware.sncro_middleware import SncroMiddleware, sncro_routes

app = FastAPI()
app.include_router(sncro_routes)
app.add_middleware(SncroMiddleware, relay_url="https://relay.sncro.net")

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


# --- Intentionally buggy sports dashboard ---

SPORTS_API = "https://www.thesportsdb.com/api/v1/json/3/eventsday.php"


async def fetch_scores():
    """Fetch sports events. Intentional bug: no timeout, no error handling."""
    # Try today first, fall back through recent days to find games
    async with httpx.AsyncClient() as client:
        all_events = []
        for offset in range(0, 4):
            d = (date.today() - timedelta(days=offset)).isoformat()
            # Bug 1: Fetches sequentially instead of in parallel
            nba = await client.get(f"{SPORTS_API}?d={d}&l=NBA")
            nhl = await client.get(f"{SPORTS_API}?d={d}&l=NHL")
            mlb = await client.get(f"{SPORTS_API}?d={d}&l=MLB")
            epl = await client.get(f"{SPORTS_API}?d={d}&l=English_Premier_League")

            for resp in [nba, nhl, mlb, epl]:
                if resp.status_code == 200:
                    data = resp.json()
                    all_events.extend(data.get("events") or [])
            if all_events:
                break  # Found games, stop looking
        return all_events


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

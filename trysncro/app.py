"""try.sncro.net — a deliberately broken page for demoing sncro."""

from datetime import date

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
    """Fetch today's sports events. Intentional bug: no timeout, no error handling."""
    today = date.today().isoformat()
    async with httpx.AsyncClient() as client:
        # Bug 1: Fetches sequentially instead of in parallel
        nba = await client.get(f"{SPORTS_API}?d={today}&l=NBA")
        nhl = await client.get(f"{SPORTS_API}?d={today}&l=NHL")
        mlb = await client.get(f"{SPORTS_API}?d={today}&l=MLB")
        epl = await client.get(f"{SPORTS_API}?d={today}&l=English_Premier_League")

        events = []
        for resp in [nba, nhl, mlb, epl]:
            if resp.status_code == 200:
                data = resp.json()
                events.extend(data.get("events") or [])
        return events


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

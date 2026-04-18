# sncro-relay

Open-source components of [sncro](https://sncro.net) — the MCP relay, the browser-side agent, and the framework plugins that let AI coding assistants inspect a live browser.

## What this repo contains

| Path | What |
|---|---|
| `relay/` | FastAPI app that exposes an [MCP](https://modelcontextprotocol.io) server plus long-poll endpoints for agent.js |
| `relay/static/agent.js` | Browser-side script injected by the middleware; pushes console + DOM data to the relay |
| `middleware/sncro_middleware.py` | FastAPI / Starlette plugin — drop-in middleware for FastAPI apps |
| `middleware/sncro_flask.py` | Flask plugin — drop-in middleware for Flask apps |
| `trysncro/` | `try.sncro.net` — a deliberately-broken demo app for exercising sncro end-to-end |

## How it works

```
 ┌──────────────┐    MCP     ┌──────────┐   long-poll   ┌─────────────┐
 │ Claude Code  │──tools────▶│  relay   │◀──────────────│  agent.js   │
 │ (or other    │            │ (relay/) │   snapshots   │ (injected   │
 │  MCP client) │◀──results──│          │──────────────▶│  by plugin) │
 └──────────────┘            └──────────┘               └─────────────┘
                                                              ▲
                                                              │ same-origin
                                                              │ cookies
                                                       ┌─────────────┐
                                                       │  your app   │
                                                       │ (plugin is  │
                                                       │  installed) │
                                                       └─────────────┘
```

1. Claude calls `create_session` (MCP tool) → relay returns a 9-digit session key + URL
2. User visits the URL in the browser where their app is running → confirms via "Allow sncro debugging?"
3. The plugin drops a cookie, agent.js is injected into subsequent HTML responses on that origin
4. agent.js pushes baseline data (console, errors) and long-polls for on-demand queries (`query_element`, `get_page_snapshot`, etc.)

## Using sncro

Most users don't need to run the relay yourself — the hosted version at `relay.sncro.net` is free-tier friendly. Register your project at [sncro.net](https://sncro.net) and grab your project key.

**FastAPI:** drop [middleware/sncro_middleware.py](middleware/sncro_middleware.py) into your project, then:
```python
from middleware.sncro_middleware import SncroMiddleware, sncro_routes

app = FastAPI(debug=True)  # sncro only loads when debug=True
if app.debug:
    app.include_router(sncro_routes)
    app.add_middleware(SncroMiddleware, relay_url="https://relay.sncro.net")
```

**Flask:** drop [middleware/sncro_flask.py](middleware/sncro_flask.py) into your project, then:
```python
from sncro_flask import init_sncro

app = Flask(__name__)
if app.debug:
    init_sncro(app, relay_url="https://relay.sncro.net")
```

Both middlewares only activate in debug mode — zero overhead in production.

## Contributing

We love new framework plugins. [CONTRIBUTING.md](CONTRIBUTING.md) has the full spec for what a plugin must do — cookies, routes, security headers — plus the test template. Django, Rails, Express, Next.js, ASP.NET, Go — all welcome.

Bug reports and security issues: see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).

The dashboard at [sncro.net](https://sncro.net) (project management, billing, admin) lives in a separate proprietary repo.

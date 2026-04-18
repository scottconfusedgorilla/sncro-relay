# sncro-relay

This is the open-source half of [sncro](https://sncro.net). It contains the MCP relay, the browser-side agent, and the framework plugins.

## Repo layout

- `relay/` — FastAPI app. Mounts an MCP server at `/tools/mcp`, exposes long-poll endpoints for agent.js under `/session/{key}/*`, serves `agent.js` from `/static/`.
- `middleware/` — framework plugins that customers install into their apps. `sncro_middleware.py` (FastAPI) and `sncro_flask.py` (Flask).
- `trysncro/` — `try.sncro.net`, a deliberately-broken demo app used for end-to-end testing.
- `tests/` — pytest suite. 44 tests covering the relay, both plugins, and end-to-end flows.

The dashboard, auth, admin, billing, and landing page live in a separate private repo.

## Tech stack

- Python 3.11+, FastAPI, Starlette
- [MCP](https://modelcontextprotocol.io) server via the [`mcp`](https://github.com/modelcontextprotocol/python-sdk) Python SDK
- Flask (for the Flask plugin and its tests)
- slowapi for rate limiting
- pytest for tests

## Running locally

```bash
pip install -r requirements.txt
pytest                          # 44 tests should pass
uvicorn relay.main:app --reload # run the relay on localhost:8000
```

## Running the demo

```bash
pip install -r trysncro/requirements.txt
DEBUG=true uvicorn trysncro.app:app --port 8001
# Browse to http://localhost:8001
```

## Testing

`pytest` at the repo root. The suite is fast (< 5s). No integration tests that hit real services.

## Commit style

Commits that deploy a new relay build are prefixed with the build number, e.g. `(build 093) Advertise tools/listChanged on the MCP server`. Security-related work is labeled with a phase letter (A through I so far). See `git log --oneline` for the shape.

## Security

Every Critical/High from the blackhat/2 static review has a line-verified fix. See `SECURITY.md` for the reporting path and the threat model.

Guidelines when adding new features:
- If it touches the enable flow, the CSRF / clickjacking defences apply
- If it adds an endpoint, consider whether it needs a rate limit
- If it handles user-supplied strings, validate them against a regex at the boundary
- If it renders user-supplied content, use DOM APIs (not `innerHTML + string`) on the client side and autoescape on the server side

## Releases

There's no formal release cadence yet. The relay is currently deployed from `master` to `relay.sncro.net`. If you add a change that needs to ship, open a PR; merging triggers the deploy.

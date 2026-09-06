# Phase 3: Central API and Database

## What it does

Phases 1-2 print results to a terminal. Phase 3 gives them somewhere
to land: a FastAPI backend (`undercover.api.server`) backed by SQLite
(`undercover.api.database`, `undercover.api.models`) that the CLI
scanners can submit their findings to instead of (or in addition to)
printing them.

```
undercover --submit path/to/email.txt          # DLP scan -> POST /dlp/scans
undercover-phish --submit path/to/email.eml     # phishing analysis -> POST /phishing/analyses
```

## Running the server

```bash
pip install -e ".[api]"
undercover-api                       # http://127.0.0.1:8000
undercover-api --host 0.0.0.0 --port 8080 --reload
```

Interactive docs (Swagger UI) are served at `/docs`, and the raw
OpenAPI schema at `/openapi.json` -- both come from FastAPI for free
and are the fastest way to try the API without writing a client.

By default it stores data in a local `undercover.db` SQLite file in
the current directory. Point it elsewhere (or at Postgres later) with:

```bash
export UNDERCOVER_DB_URL="sqlite:////absolute/path/to/undercover.db"
# or, for Postgres once you're ready:
export UNDERCOVER_DB_URL="postgresql+psycopg://user:pass@host/dbname"
```

Swapping the URL is the only change needed to move to Postgres --
`undercover.api.database` and `undercover.api.models` use SQLAlchemy's
engine-agnostic API throughout.

## Endpoints

| Method | Path                       | Purpose                                  |
|--------|----------------------------|-------------------------------------------|
| GET    | `/health`                  | Liveness check                            |
| POST   | `/dlp/scans`                | Submit a DLP scan result                  |
| GET    | `/dlp/scans`                | List scans (summary: id, source, finding_count, created_at) |
| GET    | `/dlp/scans/{id}`           | Full scan detail, including findings      |
| POST   | `/phishing/analyses`        | Submit a phishing analysis result         |
| GET    | `/phishing/analyses`        | List analyses (summary)                   |
| GET    | `/phishing/analyses/{id}`   | Full analysis detail, including rule hits |

The request/response shapes for the POST endpoints are deliberately
identical to `ScanResult.to_dict()` / `PhishingResult.to_dict()` from
Phases 1-2 plus a `source` field -- see `undercover.api.schemas`.

## The CLI client

`undercover.api.client.ApiClient` is the thing `--submit` uses under
the hood:

```python
from undercover.api.client import ApiClient

client = ApiClient(base_url="http://127.0.0.1:8000")
client.submit_dlp_scan("email.txt", scan_result)
client.submit_phishing_analysis("email.eml", phishing_result)
```

It depends only on `httpx` (part of the `api` extra), and -- like
`undercover.dlp.ner` and `undercover.phishing.classifier` -- degrades
by raising a catchable `ApiClientError` rather than crashing the
process: a scan that already ran and printed its results locally
shouldn't fail just because the API is down or `httpx` isn't
installed. `undercover --submit` and `undercover-phish --submit` both
catch this and print a warning to stderr, keeping their normal exit
code.

Configure the target API with `--api-url` or the `UNDERCOVER_API_URL`
environment variable (default `http://127.0.0.1:8000`).

## Design decisions

- **Two separate SQLAlchemy models per result type** (`DlpScan` +
  `DlpFinding`, `PhishingAnalysis` + `PhishingRuleHit`) rather than one
  generic "finding" table. A DLP finding and a phishing rule hit have
  different shapes (offsets vs. weights) and different parents; forcing
  them into one polymorphic table would need a discriminator column and
  nullable fields for whichever type doesn't apply. Two narrow tables
  are simpler to query and to reason about.
- **The client only needs `httpx`.** `undercover/api/__init__.py`
  imports `ApiClient` (client.py, httpx-only) but never the server
  modules (`server.py`, `models.py`, which need fastapi/sqlalchemy) at
  package-import time. This means the base `undercover` and
  `undercover-phish` CLIs can offer `--submit` without forcing every
  user to install the full server stack -- they only pay for `httpx`
  when the `api` extra is installed, and get a clear skip reason
  otherwise.
- **SQLite by default, Postgres via one env var.** `UNDERCOVER_DB_URL`
  is read once and handed to SQLAlchemy's `create_engine`; nothing else
  in the models or routes is SQLite-specific, so the roadmap's "Postgres
  later if you want it production-grade" is a deployment change, not a
  code change.

## Testing

```bash
pip install -e ".[dev,api]"
pytest tests/api
```

Route tests use FastAPI's `TestClient` with a fresh in-memory SQLite
database per test (via `app.dependency_overrides[get_db]` and
`StaticPool`), so they never touch a real file or leak state between
tests. `ApiClient` tests are split the same way the Phase 2 classifier
tests are: one class that runs when `httpx` is missing (asserting the
graceful-failure path) and one that runs when it's installed
(asserting the real request/response shape, via a monkeypatched
`httpx.post`).

## Known limitations

- **No auth.** Anyone who can reach the API can submit or read
  findings. Fine for a local/portfolio deployment; a real deployment
  needs at least an API key before it goes anywhere multi-tenant.
- **No de-duplication.** Submitting the same scan twice creates two
  rows. Phase 4's anomaly work and Phase 5's risk scoring will want a
  content hash or idempotency key to avoid double-counting.
- **No pagination cursor, just offset/limit.** Fine at this scale;
  would need revisiting before this held a large production dataset.

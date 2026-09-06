"""The undercover API: a central store for DLP and phishing findings.

Run it with `undercover-api` (or `uvicorn undercover.api.server:app`) and
browse the interactive docs at http://127.0.0.1:8000/docs.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from undercover.api.database import init_db
from undercover.api.routes import anomaly, audit, dlp, phishing, risk


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="undercover API",
        description=(
            "Central store for DLP scan and phishing analysis findings "
            "submitted by the undercover CLI tools (`undercover --submit`, "
            "`undercover-phish --submit`)."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    app.include_router(dlp.router)
    app.include_router(phishing.router)
    app.include_router(anomaly.router)
    app.include_router(risk.router)
    app.include_router(audit.router)

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()

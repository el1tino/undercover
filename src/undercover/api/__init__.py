"""Central API and database (Phase 3).

A FastAPI backend (undercover.api.server) backed by SQLite
(undercover.api.database, undercover.api.models) that the CLI scanners
from Phases 1-2 submit their findings to via undercover.api.client,
instead of only printing them to console. See
docs/phase3-api-and-database.md and docs/roadmap.md.

Only undercover.api.client is imported here -- it needs just httpx.
Importing the server (undercover.api.server) requires the full `api`
extra (fastapi, sqlalchemy, uvicorn); do that explicitly rather than
forcing it on everyone who imports this package for the client alone.
"""

from undercover.api.client import ApiClient, ApiClientError

__all__ = ["ApiClient", "ApiClientError"]

"""SQLite (or any SQLAlchemy-supported) database setup for the API server."""

from __future__ import annotations

import os
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DEFAULT_DB_URL = "sqlite:///./undercover.db"


def database_url() -> str:
    return os.environ.get("UNDERCOVER_DB_URL", DEFAULT_DB_URL)


class Base(DeclarativeBase):
    pass


_engine = None
_session_factory: sessionmaker | None = None


def get_engine():
    global _engine
    if _engine is None:
        url = database_url()
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args)
    return _engine


def get_session_factory() -> sessionmaker:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(), autoflush=False, autocommit=False
        )
    return _session_factory


def init_db() -> None:
    """Create all tables that don't exist yet. Safe to call repeatedly."""
    Base.metadata.create_all(bind=get_engine())


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yields a session, closes it after the request."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()

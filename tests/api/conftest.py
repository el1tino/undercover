"""Shared fixtures for API route tests.

Requires the `api` extra (fastapi, sqlalchemy). The `client` fixture
defers all fastapi/sqlalchemy imports to when it actually runs (rather
than importing them at module level here) and calls
`pytest.importorskip` inside the fixture body -- doing that at
conftest *module* level instead escapes as a hard collection error
rather than a clean per-test skip, since this file is loaded as an
initial conftest before pytest's skip machinery is fully set up. The
test modules that use this fixture (test_health.py, test_dlp_routes.py,
test_phishing_routes.py) each call `pytest.importorskip("fastapi")` at
their own module level, which is the supported way to skip a whole
test file.
"""

import pytest


@pytest.fixture()
def client():
    pytest.importorskip("fastapi")
    pytest.importorskip("sqlalchemy")

    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from undercover.api.database import Base, get_db
    from undercover.api.server import app

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        session = testing_session_local()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)

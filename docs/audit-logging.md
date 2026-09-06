# Audit Logging

The fourth "later addition": every submission to the API now leaves an
append-only trail of *what* happened, *when*, and from *which* source
IP -- useful for after-the-fact investigation even though this API
has no login system to say *who*.

## What it does

Every `POST` that creates a resource (`/dlp/scans`, `/phishing/analyses`,
`/risk/assessments`) writes one `AuditLogEntry` immediately after
committing that resource:

| Field           | Example                                    |
|-----------------|---------------------------------------------|
| `timestamp`      | `2026-01-15T14:32:07Z`                       |
| `action`          | `phishing_analysis.created`                  |
| `resource_type`    | `phishing_analysis`                          |
| `resource_id`       | `42`                                          |
| `source_ip`          | `203.0.113.7`                                 |
| `detail`              | `source='invoice.eml', verdict='phishing'`     |

**`GET /audit/log`** lists entries newest-first, with optional
`action` / `resource_type` filters and the usual `limit`/`offset`
pagination.

## Why this, given there's no auth

Phase 3's Known Limitations already note this API has no
authentication -- anyone who can reach it can submit or read findings.
That means a real *who* (a logged-in user, an API key identity) isn't
available to record. What's still available and still useful:

- **When** something was created, precisely.
- **From what source IP** -- a burst of submissions from one address is
  visible even without knowing whose address it is.
- **What** was created and its outcome (a phishing verdict, a risk
  level) without needing to cross-reference the full resource.

This is a genuinely useful trail for "when did assessment #42 get
created, and was anything else submitted around the same time from the
same place" -- it's just not a substitute for real access control or
user-level accountability, which would need an actual auth system
first (not part of this project's current scope).

## Design decisions

- **Failures are caught and logged, never allowed to break the
  submission.** `record_audit_event()` runs after the primary resource
  is already committed; each route wraps the call in
  `try/except Exception: logger.exception(...)`, the same pattern
  used for alerting in `POST /risk/assessments`. A bug in audit logging
  must never turn a successful submission into a 500.
- **No new dependency.** Audit logging uses only what the `api` extra
  already requires (FastAPI's `Request` object for the source IP,
  SQLAlchemy for storage) -- there's no `audit` extra to install.
- **It's a separate module (`undercover.api.audit`) called from three
  routes, not middleware.** FastAPI middleware would auto-log every
  request uniformly, including reads, but a `GET` doesn't need to be
  in an audit trail the way a state-changing `POST` does, and
  middleware can't easily express "here's the resource ID this action
  created" the way a per-route call after `db.refresh()` can. Explicit
  calls at 3 call sites is a small amount of duplication in exchange
  for that specificity.

## Testing

```bash
pip install -e ".[dev,api]"
pytest tests/api/test_audit.py
```

Covers: an entry is created for each resource type with the right
action/resource_id/detail, newest-first ordering, both filters, limit
pagination, and -- mirroring
`tests/api/test_risk_routes.py::TestAlertingIntegration` -- that a
broken `record_audit_event` (monkeypatched to raise) never prevents
the underlying submission from succeeding, for all three routes.

## Known limitations

- **No real identity.** As covered above -- this is IP + timestamp +
  action, not a user-attributed audit trail. A future auth system
  would want to extend `AuditLogEntry` with an actor/API-key-id field.
- **Only creation is logged.** There's no update or delete on any
  resource today, so there's nothing else to audit yet -- if the
  triage/case-management view (another open roadmap item) adds status
  changes, those should get their own audit actions
  (e.g. `risk_assessment.status_changed`).
- **`source_ip` is whatever `Request.client.host` reports**, which is
  the direct TCP peer -- behind a reverse proxy or load balancer
  without `X-Forwarded-For` handling, every entry would show the
  proxy's IP rather than the real client's. Not handled here.

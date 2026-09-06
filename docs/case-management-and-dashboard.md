# Case Management, Trend Dashboard, and Server-Side Reporting

Three roadmap items landed together because they share a foundation:
a "case" is a `RiskAssessment` viewed for triage, the dashboard is
aggregate queries over the same tables every other route already
writes to, and the new `POST /report/email` endpoint is what makes
both worth having -- a way to get assessments into the system without
running the CLI first.

## Case management

Every `RiskAssessment` now has a `status`: `open` (default),
`investigating`, `resolved`, or `false_positive`.

- **`PATCH /risk/assessments/{id}/status`** -- JSON API, for
  programmatic use.
- **`GET /ui/cases`** -- a server-rendered table, filterable by
  `?status=` and `?risk_level=`.
- **`GET /ui/cases/{id}`** -- detail view: every contributing factor
  (from Phase 5's `RiskFactor` rows) with its weight, value, and
  human-readable detail, plus buttons to change status.
- **`POST /ui/cases/{id}/status`** -- the form-submission counterpart
  to the PATCH endpoint (HTML forms don't support `PATCH`), redirects
  back to the detail page (303) after updating.

Both status-change paths funnel through the same update logic and
both write an audit entry (`risk_assessment.status_changed`) via
`undercover.api.audit.record_audit_event` -- see docs/audit-logging.md.

### Why no separate `Case` table

A `RiskAssessment` already has everything a case needs: source,
sender, risk score/level, and the factors that produced it. Adding a
`status` column to the existing table is a small, additive change
(the same pattern `sender_email` on `PhishingAnalysis` used for Phase
4's join key); a separate `Case` table referencing `RiskAssessment`
would just be an extra join for no additional information. If this
ever needs to track multiple assessments under one investigation (a
campaign spanning several emails), *that* would justify a real `Case`
entity -- but that's not what exists today.

## Trend dashboard

**`GET /ui/dashboard`** aggregates straight from the database with
plain SQLAlchemy `group_by`/`count()` queries -- no new tables, no
scheduled job computing rollups ahead of time:

- Total DLP scans, phishing analyses, risk assessments.
- Phishing verdict distribution, risk level distribution, case status
  distribution -- each rendered as a small CSS bar chart (a `<div>`
  with `width: N%`, no charting library, no external CDN).
- **MITRE ATT&CK technique frequency**, computed by counting stored
  `PhishingRuleHit.name` values and mapping each through
  `undercover.mitre.techniques_for_rule_hit` -- the exact same
  function Phase 2's rule hits and the API's phishing-analysis
  responses already use, so the dashboard's numbers are guaranteed
  consistent with what `undercover-phish` shows per-message.
- Currently-anomalous senders (Phase 4's `AnomalyDetector`, run
  directly against the database rather than through
  `GET /anomaly/senders` -- see "Why /report/email queries the
  database directly" below for the same reasoning).
- The 10 most recent cases.

No JavaScript, no CDN dependency, works with cookies/JS disabled --
consistent with this being a server-rendered admin view, not a
client-side app.

## `POST /report/email`: server-side analysis

This is the piece that makes the case list and dashboard worth
building, and what powers the browser extension (see
docs/browser-extension.md): a single HTTP endpoint that runs the same
pipeline `undercover-risk` runs locally -- `DLPScanner`,
`PhishingDetector`, `analyze_headers`, and a sender-anomaly check --
entirely server-side, on a raw email string.

```bash
curl -X POST http://localhost:8000/report/email \
  -H "Content-Type: application/json" \
  -d '{"source": "reported-by-jane.eml", "raw_email": "<full raw email>"}'
```

It persists **both** a `PhishingAnalysis` and a `RiskAssessment` (the
same two resources `undercover-phish --submit` and
`undercover-risk --submit` would create if run separately), and
returns the assessment's fields plus its rule hits (with MITRE tags)
inline, so a caller doesn't need a second request to see *why* an
email was flagged.

### Why persist a PhishingAnalysis too, not just the RiskAssessment

An earlier version of this endpoint only persisted the
`RiskAssessment` -- simpler, since that's the one thing being reported
on. Manual testing caught the gap: a sender reported only through this
endpoint never showed up in `PhishingAnalysis`, so Phase 4's anomaly
detection (which reads that table) never learned about them, and the
dashboard's MITRE technique table under-counted. Persisting both
means a reported email is exactly as "real" to the rest of the system
as one submitted through the CLI -- `tests/api/test_report_routes.py`
has a test that reports the same aggressive sender repeatedly and
confirms they get flagged by `GET /anomaly/senders` afterward,
proving the feedback loop actually closes.

### Why it queries the database directly for the anomaly check

`undercover-risk` (a separate local process) has to call
`GET /anomaly/senders` over HTTP because it isn't the API server. This
endpoint *is* the API server, already holding a session on the exact
database that route would query -- an HTTP call to itself would be
pure overhead. It calls `undercover.anomaly.detector.AnomalyDetector`
directly instead.

## Testing

```bash
pip install -e ".[dev,api]"
pytest tests/api/test_ui_routes.py tests/api/test_report_routes.py tests/api/test_risk_routes.py
```

UI route tests assert on substrings in the rendered HTML (source,
sender, badges, factor details) rather than parsing the DOM -- enough
to catch a broken template or a wrong query without needing a browser.
Report-endpoint tests cover both persisted resources being created,
both audit actions firing, graceful degradation when scikit-learn
isn't installed, and the anomaly-feedback loop described above.

## Known limitations

- **No authentication on the UI or the report endpoint**, same
  standing limitation as the rest of the API (see
  docs/phase3-api-and-database.md). Anyone who can reach the server
  can view cases, change their status, or submit reports.
- **The dashboard re-queries and re-aggregates on every request.**
  Fine at the data volumes a demo or small deployment would see;
  a large production dataset would want cached/materialized rollups
  instead of live `group_by` queries on every page load.
- **No pagination on the case list or dashboard's recent-cases
  table** -- both cap at a fixed limit (100 and 10 respectively)
  rather than paging through everything.

# Roadmap

`undercover` is being built in phases, each one a working increment on
top of the last.

## Phase 1 — DLP scanner ✅ implemented

A local CLI tool that scans email/text content for sensitive data:
regex for structured PII (SSNs, credit cards, API keys, credentials)
plus spaCy NER for names, addresses, and other unstructured PII. See
[`phase1-dlp-scanner.md`](phase1-dlp-scanner.md).

## Phase 2 — Phishing detection ✅ implemented

Layer in phishing classification: a rule-based pass (suspicious links,
urgency language, spoofed display names, mismatched sender domains)
combined with a scikit-learn ML classifier trained on a labeled
phishing/ham dataset. Rule-based catches the obvious stuff; the
classifier handles what rules miss. See
[`phase2-phishing-detection.md`](phase2-phishing-detection.md).

## Phase 3 — Central API and database ✅ implemented

This is where it becomes a real client-server app: a FastAPI backend
with SQLite to start (Postgres later for a production-grade setup), so
the local CLI scanner submits findings to a hosted API and shared
database instead of just printing to console. FastAPI's built-in
`/docs` is used for interactive API testing while building it out. See
[`phase3-api-and-database.md`](phase3-api-and-database.md).

## Phase 4 — Anomaly detection ✅ implemented

Add behavioral/statistical detection on top of the rule-based work:
isolation forests or clustering over sender metadata (sending
patterns, volume, timing, relationship graphs) to flag things that
don't fit a known rule but still look wrong. See
[`phase4-anomaly-detection.md`](phase4-anomaly-detection.md). Note:
relationship-graph features are still open -- see that doc's Known
Limitations.

## Phase 5 — Risk scoring, header analysis, SIEM export ✅ implemented

Tie it together: SPF/DKIM/DMARC header validation, a unified risk
score combining all the signals from earlier phases, and export in
SIEM-friendly formats (CEF or JSON) so it reads as something that
could plug into a real SOC pipeline. See
[`phase5-risk-scoring.md`](phase5-risk-scoring.md). Note: header
validation parses the Authentication-Results header a message already
carries rather than performing live DNS/cryptographic verification --
see that doc's Known Limitations for why.

**All five core phases are now implemented.** What's left is the
"later additions" below.

## Later additions

Once the core works:

- [x] **Attachment scanning against VirusTotal or MalwareBazaar** ✅
      implemented. Hash-only lookups (never uploads), folded into
      `undercover-risk` as an opt-in fifth signal
      (`--check-attachments`). See
      [`attachment-scanning.md`](attachment-scanning.md).
- [x] **Alerting** ✅ implemented. Webhook and Slack channels, fired
      centrally from `POST /risk/assessments` on every submission that
      crosses a configurable threshold, plus a standalone
      `undercover-risk --alert-threshold` path. See
      [`alerting.md`](alerting.md).
- [x] **MITRE ATT&CK tagging on detections** ✅ implemented. Phase 2
      phishing rule hits carry technique IDs (T1566, T1566.002, T1656);
      DLP findings and the anomaly/header signals are deliberately left
      untagged since they don't represent a discrete adversary
      technique. See [`mitre-attack-tagging.md`](mitre-attack-tagging.md).
- [x] **Audit logging** ✅ implemented. Every submission to
      `/dlp/scans`, `/phishing/analyses`, and `/risk/assessments`
      writes an append-only entry (what, when, source IP), queryable
      via `GET /audit/log`. See [`audit-logging.md`](audit-logging.md).
- [x] **A basic triage/case-management view** ✅ implemented.
      `RiskAssessment.status` (open/investigating/resolved/false_positive)
      plus server-rendered `GET /ui/cases` and `GET /ui/cases/{id}`
      views with a status-change form (Jinja2, no external CDN).
- [x] **A trend dashboard** ✅ implemented. `GET /ui/dashboard`:
      verdict/risk-level/status distributions, MITRE technique
      frequency, currently-anomalous senders, recent cases -- all
      server-computed aggregates, no client-side JS.
      See [`case-management-and-dashboard.md`](case-management-and-dashboard.md),
      which also covers the new `POST /report/email` endpoint these
      two views are built on.
- [ ] A browser extension for one-click reporting

## Engineering hygiene

pytest unit tests land alongside each module as it's built, and this
`docs/` folder plus the top-level README are kept current -- this is a
portfolio piece, so how it reads matters as much as whether it runs.

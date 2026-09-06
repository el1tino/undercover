# Roadmap

`undercover` is being built in phases, each one a working increment on
top of the last.

## Phase 1 — DLP scanner ✅ implemented

A local CLI tool that scans email/text content for sensitive data:
regex for structured PII (SSNs, credit cards, API keys, credentials)
plus spaCy NER for names, addresses, and other unstructured PII. See
[`phase1-dlp-scanner.md`](phase1-dlp-scanner.md).

## Phase 2 — Phishing detection

Layer in phishing classification: a rule-based pass (suspicious links,
urgency language, spoofed display names, mismatched sender domains)
combined with a scikit-learn ML classifier trained on a labeled
phishing/ham dataset. Rule-based catches the obvious stuff; the
classifier handles what rules miss.

## Phase 3 — Central API and database

This is where it becomes a real client-server app: a FastAPI backend
with SQLite to start (Postgres later for a production-grade setup), so
the local CLI scanner submits findings to a hosted API and shared
database instead of just printing to console. FastAPI's built-in
`/docs` is used for interactive API testing while building it out.

## Phase 4 — Anomaly detection

Add behavioral/statistical detection on top of the rule-based work:
isolation forests or clustering over sender metadata (sending
patterns, volume, timing, relationship graphs) to flag things that
don't fit a known rule but still look wrong.

## Phase 5 — Risk scoring, header analysis, SIEM export

Tie it together: SPF/DKIM/DMARC header validation, a unified risk
score combining all the signals from earlier phases, and export in
SIEM-friendly formats (CEF or JSON) so it reads as something that
could plug into a real SOC pipeline.

## Later additions

Once the core works: attachment scanning against VirusTotal or
MalwareBazaar, alerting, a basic triage/case-management view, audit
logging, a browser extension for one-click reporting, a trend
dashboard, and MITRE ATT&CK tagging on detections.

## Engineering hygiene

pytest unit tests land alongside each module as it's built, and this
`docs/` folder plus the top-level README are kept current -- this is a
portfolio piece, so how it reads matters as much as whether it runs.

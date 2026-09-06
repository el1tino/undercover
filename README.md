# undercover

A data-loss-prevention (DLP) and phishing-detection toolkit, built in
phases from a local CLI scanner up to a full client-server security
pipeline with risk scoring and SIEM export.

## Status

**Everything in [`docs/roadmap.md`](docs/roadmap.md) is implemented**:
the five core phases (DLP scanning, phishing detection, a central
API + database, sender anomaly detection, unified risk scoring with
SIEM export) and every "later addition" (attachment scanning against
VirusTotal/MalwareBazaar, webhook/Slack alerting, MITRE ATT&CK
tagging, audit logging, a triage case-management view, a trend
dashboard, and a browser extension for one-click reporting). The
roadmap doc has the full narrative of how each piece was built and
why, in order.

## Quick start

The fastest path to running the whole thing end to end -- everything
below is covered in more depth (and can be installed piecemeal) in the
phase/feature sections that follow.

```bash
git clone https://github.com/el1tino/undercover.git
cd undercover
python3 -m venv .venv
source .venv/bin/activate

# Every extra in one shot (dev tools + all optional features)
pip install -e ".[dev,ner,phishing,api,anomaly,attachments,alerting]"
python -m spacy download en_core_web_sm   # needed for the [ner] extra to actually load a model
```

Run the test suite:

```bash
pytest -q -rs   # 269 passed, 8 skipped with every extra installed above

# Or with just the core + dev extras, to see the project degrade gracefully
# without the optional ML/NER/API dependencies:
pip install -e ".[dev]"
pytest -q -rs   # 177 passed, 44 skipped
```

Start the API and open the web UI:

```bash
undercover-api   # http://127.0.0.1:8000
# Interactive API docs:  http://127.0.0.1:8000/docs
# Trend dashboard:       http://127.0.0.1:8000/ui/dashboard
# Case triage view:      http://127.0.0.1:8000/ui/cases
```

Try the CLIs against the bundled examples:

```bash
undercover examples/sample_emails/leaky_email.txt              # Phase 1: DLP scan
undercover-phish examples/sample_emails/phishing_example.eml   # Phase 2: phishing detection
undercover-risk examples/sample_emails/phishing_example.eml    # Phase 5: unified risk score

# Submit results to the running API instead of just printing them
undercover-risk --submit examples/sample_emails/phishing_example.eml
undercover-anomaly   # Phase 4: per-sender anomaly report, once a few analyses are submitted
```

Load the browser extension (needs the API running from above):
`chrome://extensions` -> enable **Developer mode** -> **Load unpacked**
-> select `browser-extension/`. See
[`docs/browser-extension.md`](docs/browser-extension.md) for details.

Everything else -- attachment scanning, alerting, MITRE ATT&CK tagging,
audit logging -- works the same way once the API is running; see the
sections below for each one's specific setup (most need an API key or
environment variable) and the `docs/*.md` link for the design behind
it.

## Phase 1: DLP scanner

Scans email or text content for sensitive data:

- **Structured PII / secrets** (regex + validation): SSNs, credit card
  numbers (Luhn-checked), email addresses, phone numbers, IPv4
  addresses, AWS keys, GitHub/Slack tokens, PEM private-key blocks,
  JWTs, and generic credential assignments.
- **Unstructured PII** (spaCy NER, optional): person names, addresses,
  organizations.

See [`docs/phase1-dlp-scanner.md`](docs/phase1-dlp-scanner.md) for
design details and known limitations.

### Install

```bash
pip install -e .

# Optional: unstructured PII detection via spaCy NER
pip install -e ".[ner]"
python -m spacy download en_core_web_sm
```

### Use

```bash
# Scan a file
undercover examples/sample_emails/leaky_email.txt

# Scan stdin
cat email.txt | undercover

# Machine-readable output
undercover --json examples/sample_emails/leaky_email.txt

# Regex-only (skip spaCy)
undercover --no-ner examples/sample_emails/leaky_email.txt

# Exit 1 if anything is found (CI / pre-commit)
undercover --fail-on-find examples/sample_emails/leaky_email.txt
```

## Phase 2: Phishing detection

Analyzes an email for phishing indicators: a rule-based pass
(suspicious links, urgency language, spoofed display names,
sender/reply-to mismatches) combined with an optional scikit-learn
classifier, producing a `clean` / `suspicious` / `phishing` verdict.

See [`docs/phase2-phishing-detection.md`](docs/phase2-phishing-detection.md)
for design details, including why the bundled dataset is a toy and how
to swap in a real one.

### Install

```bash
pip install -e ".[phishing]"
```

### Use

```bash
# Analyze a .eml file
undercover-phish examples/sample_emails/phishing_example.eml

# Machine-readable output
undercover-phish --json examples/sample_emails/phishing_example.eml

# Rules only (skip the ML classifier)
undercover-phish --no-ml examples/sample_emails/legit_example.eml

# Train and save a model (default: the bundled demo dataset)
undercover-phish-train --out models/phishing_classifier.joblib
undercover-phish --model models/phishing_classifier.joblib examples/sample_emails/phishing_example.eml
```

### Develop

```bash
pip install -e ".[dev,phishing]"
pytest
```

## Phase 3: Central API and database

A FastAPI + SQLite backend the CLI scanners submit their results to,
instead of only printing them. Interactive docs come free at `/docs`.

See [`docs/phase3-api-and-database.md`](docs/phase3-api-and-database.md)
for endpoint details and design decisions.

### Install and run

```bash
pip install -e ".[api]"
undercover-api                # http://127.0.0.1:8000, docs at /docs
```

### Use

```bash
# Submit a DLP scan to the API instead of just printing it
undercover --submit examples/sample_emails/leaky_email.txt

# Submit a phishing analysis
undercover-phish --submit examples/sample_emails/phishing_example.eml

# Point at a non-default API (or set $UNDERCOVER_API_URL)
undercover --submit --api-url http://localhost:8080 email.txt
```

### Develop

```bash
pip install -e ".[dev,api]"
pytest tests/api
```

## Phase 4: Anomaly detection

Flags senders whose *aggregate behavior* looks wrong -- unusual
volume, unusually high risk scores, an unusually high phishing ratio,
suspiciously regular send timing -- even when no single message they
sent tripped a Phase 2 rule. Computed on demand from the phishing
analyses Phase 3 has stored, via an optional scikit-learn
`IsolationForest`.

See [`docs/phase4-anomaly-detection.md`](docs/phase4-anomaly-detection.md)
for how the features are built and the model's limitations.

### Install

```bash
pip install -e ".[api,anomaly]"   # anomaly detection runs server-side
```

### Use

```bash
# Submit a few phishing analyses first so there's something to compare
undercover-phish --submit examples/sample_emails/phishing_example.eml
undercover-phish --submit examples/sample_emails/legit_example.eml

# Then fetch the per-sender anomaly report
undercover-anomaly
undercover-anomaly --json
```

### Develop

```bash
pip install -e ".[dev,api,anomaly]"
pytest tests/anomaly tests/api/test_anomaly_routes.py
```

## Phase 5: Risk scoring, header analysis, SIEM export

Ties the earlier phases together into one command: `undercover-risk`
runs the DLP scanner and phishing detector on an email, parses its
SPF/DKIM/DMARC `Authentication-Results` header, checks whether the
sender is currently flagged anomalous, and fuses all of that into one
risk score, level, and CEF/JSON export a SIEM can ingest.

See [`docs/phase5-risk-scoring.md`](docs/phase5-risk-scoring.md) for
the scoring model, the CEF format, and why header validation means
parsing an existing header rather than live DNS/cryptographic checks.

### Install

```bash
pip install -e .   # core (DLP + phishing rules + headers + CEF/JSON) needs no extras
pip install -e ".[phishing,api,anomaly]"  # + ML classifier, --submit, anomaly check
```

### Use

```bash
# Human-readable risk assessment
undercover-risk examples/sample_emails/phishing_example.eml

# SIEM-friendly export
undercover-risk --format cef examples/sample_emails/phishing_example.eml
undercover-risk --format json examples/sample_emails/phishing_example.eml

# Store the assessment via the API
undercover-risk --submit examples/sample_emails/phishing_example.eml

# CI/pre-commit gate
undercover-risk --fail-on-risk high examples/sample_emails/phishing_example.eml
```

### Develop

```bash
pip install -e ".[dev,api,phishing,anomaly]"
pytest tests/risk tests/api/test_risk_routes.py
```

## Attachment scanning (VirusTotal + MalwareBazaar)

The first "later addition" from the roadmap: checks each email
attachment's SHA-256 hash (never the file itself) against VirusTotal
and MalwareBazaar, folded into `undercover-risk` as an opt-in fifth
signal.

See [`docs/attachment-scanning.md`](docs/attachment-scanning.md) for
why it's hash-lookup-only, setup, and limitations (it catches known
malware, not novel samples).

### Install and configure

```bash
pip install -e ".[attachments]"
export VT_API_KEY="your-virustotal-api-key"            # optional
export MALWAREBAZAAR_API_KEY="your-abuse.ch-auth-key"  # optional
```

### Use

```bash
undercover-risk --check-attachments suspect_email.eml
```

### Develop

```bash
pip install -e ".[dev,attachments]"
pytest tests/attachments
```

## Alerting (webhook + Slack)

The second "later addition": a high/critical risk assessment now
triggers a notification instead of just sitting in the database.
Fires centrally from `POST /risk/assessments` on every submission
(regardless of which client submitted it), with a standalone CLI path
too.

See [`docs/alerting.md`](docs/alerting.md) for channel details and why
alerting lives in the API rather than each CLI.

### Install and configure

```bash
pip install -e ".[alerting]"   # or [api] -- both just need httpx
export UNDERCOVER_ALERT_WEBHOOK_URL="https://example.com/your-webhook"   # optional
export UNDERCOVER_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..." # optional
export UNDERCOVER_ALERT_THRESHOLD="high"   # optional, this is the default
```

### Use

```bash
# Fires automatically via the API on every submission that crosses the threshold
undercover-risk --submit suspect_email.eml

# Or standalone, no API involved
undercover-risk --alert-threshold high suspect_email.eml
```

### Develop

```bash
pip install -e ".[dev,alerting]"
pytest tests/alerting
```

## MITRE ATT&CK tagging

The third "later addition": phishing rule hits now carry the ATT&CK
technique(s) they correspond to (e.g. `T1566.002 -- Spearphishing
Link`), shown in `undercover-phish`, summarized in `undercover-risk`,
and exposed by the API. No new dependency, no database migration --
DLP findings and the anomaly/header signals are deliberately left
untagged, since they describe message content or aggregate context
rather than one discrete adversary technique.

See [`docs/mitre-attack-tagging.md`](docs/mitre-attack-tagging.md) for
the full mapping and why some detections are intentionally untagged.

```bash
undercover-phish suspect_email.eml          # per-rule-hit ATT&CK tags
undercover-risk suspect_email.eml           # consolidated summary at the bottom
pytest tests/test_mitre.py                  # no extra install needed
```

## Audit logging

The fourth "later addition": every submission to the API now leaves a
trail -- what happened, when, and from which source IP -- queryable
via `GET /audit/log`. No new extra to install; a broken audit write
can never break the submission it's auditing.

See [`docs/audit-logging.md`](docs/audit-logging.md) for what's logged
and why it can't record a real "who" without an auth system.

```bash
undercover --submit examples/sample_emails/leaky_email.txt
curl http://127.0.0.1:8000/audit/log
```

## Case management, trend dashboard, and server-side reporting

Two more "later additions," built together: `RiskAssessment` now has
a triage `status` (open/investigating/resolved/false_positive), with
server-rendered pages to view and change it, plus a dashboard of
aggregate stats -- all plain HTML/CSS, no client-side JS or CDN. Both
are powered by a new `POST /report/email` endpoint that runs the full
local analysis pipeline (DLP + phishing + headers + anomaly check)
server-side on raw email text, which is also what the browser
extension below talks to.

See [`docs/case-management-and-dashboard.md`](docs/case-management-and-dashboard.md).

```bash
undercover-api   # then open http://127.0.0.1:8000/ui/dashboard and /ui/cases

# Report an email for full analysis without the CLI:
curl -X POST http://127.0.0.1:8000/report/email \
  -H "Content-Type: application/json" \
  -d '{"source": "reported.eml", "raw_email": "<raw email text>"}'
```

```bash
pip install -e ".[dev,api]"
pytest tests/api/test_ui_routes.py tests/api/test_report_routes.py
```

## Browser extension

The last "later addition": a Manifest V3 Chrome/Edge extension for
one-click phishing reporting. Paste an email's raw source (or capture
the current page's visible text as a best-effort fallback) into the
popup, click Report, and it POSTs to `/report/email` and shows the
verdict right there -- no local Python or CLI needed to use it.

See [`docs/browser-extension.md`](docs/browser-extension.md) for
setup, why it can reach `localhost` without CORS trouble, and how it
was verified end-to-end with Playwright driving a real Chromium load.

```bash
# chrome://extensions -> Developer mode -> Load unpacked -> browser-extension/
```

## Project layout

```
src/undercover/
├── cli.py         # CLI entry point (undercover)
├── dlp/           # Phase 1 -- implemented
├── phishing/      # Phase 2 -- implemented
├── api/           # Phase 3 -- implemented
├── anomaly/       # Phase 4 -- implemented
├── attachments/   # VirusTotal + MalwareBazaar hash lookup -- implemented
├── alerting/      # webhook + Slack notifications -- implemented
└── risk/          # Phase 5 -- implemented
browser-extension/ # Manifest V3 one-click reporting extension (separate JS codebase)
tests/           # pytest suite, mirrors src/ layout
docs/            # architecture notes + per-phase design docs
examples/        # sample inputs for manual testing
```

See [`docs/architecture.md`](docs/architecture.md) for design
decisions and how later phases plug into what exists today.

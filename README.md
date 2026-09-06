# undercover

A data-loss-prevention (DLP) and phishing-detection toolkit, built in
phases from a local CLI scanner up to a full client-server security
pipeline with risk scoring and SIEM export.

## Status

**All five core phases are implemented**: DLP scanning, phishing
detection, a central API + database, sender anomaly detection, and
unified risk scoring with SIEM export. See
[`docs/roadmap.md`](docs/roadmap.md) for what's next (the "later
additions" -- attachment scanning, alerting, a dashboard, and so on)
and why the phases were ordered the way they were.

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
tests/           # pytest suite, mirrors src/ layout
docs/            # architecture notes + per-phase design docs
examples/        # sample inputs for manual testing
```

See [`docs/architecture.md`](docs/architecture.md) for design
decisions and how later phases plug into what exists today.

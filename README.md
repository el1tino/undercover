# undercover

A data-loss-prevention (DLP) and phishing-detection toolkit, built in
phases from a local CLI scanner up to a full client-server security
pipeline with risk scoring and SIEM export.

## Status

**Phases 1 (DLP scanner) and 2 (phishing detection) are implemented.**
Phases 3-5 are scaffolded as stub packages with their design documented
in [`docs/roadmap.md`](docs/roadmap.md); see that file for what's
coming next and why the phases are ordered the way they are.

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

## Project layout

```
src/undercover/
├── cli.py       # CLI entry point (undercover)
├── dlp/         # Phase 1 -- implemented
├── phishing/    # Phase 2 -- implemented
├── api/         # Phase 3 -- planned
├── anomaly/     # Phase 4 -- planned
└── risk/        # Phase 5 -- planned
tests/           # pytest suite, mirrors src/ layout
docs/            # architecture notes + per-phase design docs
examples/        # sample inputs for manual testing
```

See [`docs/architecture.md`](docs/architecture.md) for design
decisions and how later phases plug into what exists today.

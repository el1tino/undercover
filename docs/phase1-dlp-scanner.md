# Phase 1: DLP Scanner

## What it does

`undercover.dlp.DLPScanner` scans arbitrary text (email bodies, pasted
logs, files) for two categories of sensitive data:

1. **Structured PII and credential-shaped secrets**, via regex rules in
   `undercover.dlp.patterns`: SSNs, credit card numbers, email
   addresses, phone numbers, IPv4 addresses, AWS access/secret keys,
   GitHub tokens, Slack tokens, generic `key: value` credential
   assignments, PEM private-key blocks, and JWTs.
2. **Unstructured PII**, via spaCy named-entity recognition in
   `undercover.dlp.ner`: person names, locations/addresses,
   organizations, and nationality/group references.

Regex detection has no external dependencies and always runs. NER is
optional (`pip install undercover[ner]` plus
`python -m spacy download en_core_web_sm`) and degrades gracefully --
if spaCy or the model isn't installed, the scanner just skips that
pass and says why, instead of erroring out.

## Why validators matter

A naive `\d{3}-\d{2}-\d{4}` regex flags every phone extension and
invoice number that happens to have the right shape. Two mitigations
are used throughout `patterns.py`:

- **Checksums where one exists.** Credit card numbers run through the
  Luhn algorithm; only digit runs that actually pass it become
  findings.
- **Range checks where a checksum doesn't exist.** SSNs reject
  known-invalid area numbers (`000`, `666`, `9xx`) and all-zero group
  or serial segments; IPv4 addresses reject octets above 255.

This cuts obvious false positives but these are still heuristics --
the confidence score on each `Finding` reflects that (e.g. a bare
40-character base64-looking string that might be an AWS secret key
gets confidence 0.3, not 0.95).

## CLI usage

```bash
# Scan a file
undercover path/to/email.txt

# Scan stdin
cat email.txt | undercover

# Machine-readable output (for piping into Phase 3's API later)
undercover --json path/to/email.txt

# Skip the spaCy pass (faster, no model required)
undercover --no-ner path/to/email.txt

# Exit non-zero on any finding (for CI / pre-commit hooks)
undercover --fail-on-find path/to/email.txt
```

Example output:

```
Found 2 potential issue(s) in email.txt:

  [regex] Credit Card Number             ************1111     (offset 42-58, confidence 0.95)
  [regex] Email Address                  ***********@acme.com (offset 90-108, confidence 0.60)
```

Findings are always redacted (all but the last 4 characters masked) in
both human-readable and `--json` output.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/dlp tests/test_cli.py
```

Tests cover the Luhn/SSN/IP validators directly, each regex detector
against a known-good and known-bad example, redaction behavior, and
graceful NER fallback when spaCy isn't installed (the CI/dev
environment for this repo does not ship the spaCy model, so the NER
test asserts the skip-reason path rather than requiring the model).

## Known limitations

- The generic API-key/secret regex is intentionally loose (any
  `key: value`-shaped assignment with an 8+ character value) and will
  have false positives; it's a low-confidence signal meant to be
  combined with others later, not a standalone verdict.
- Phone number and email detection are shape-based only -- no MX
  lookup, no carrier validation.
- NER quality is only as good as `en_core_web_sm`; it will miss
  non-US name formats and occasionally mislabel organizations as
  people.

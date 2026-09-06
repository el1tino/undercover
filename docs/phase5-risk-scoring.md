# Phase 5: Risk Scoring, Header Analysis, and SIEM Export

## What it does

Phases 1-4 each look at one thing: sensitive data in the body, a
phishing verdict for the message, whether the sender behaves like an
outlier. Phase 5 is the "tie it together" phase the roadmap describes:
it adds a fourth signal (email authentication headers) and fuses
whichever of the four are available into one risk score, level, and
SIEM-exportable event -- via a single CLI, `undercover-risk`, that
runs everything in one pass over an email.

```bash
undercover-risk suspect_email.eml
undercover-risk --format cef suspect_email.eml    # for a SIEM
undercover-risk --submit suspect_email.eml         # store it via the API
```

## The four signals

1. **Phishing** (`undercover.phishing.detector.PhishingResult.combined_score`)
   -- from Phase 2, unchanged.
2. **DLP** (`undercover.dlp.scanner.ScanResult.findings`) -- from Phase 1,
   combined via a noisy-OR over each finding's confidence: the
   probability *at least one* finding is real, treating each as an
   independent (imperfect) piece of evidence, rather than an arbitrary
   linear scaling by count.
3. **Header authentication** (`undercover.risk.headers.HeaderAuthReport`)
   -- new in this phase. Parses the `Authentication-Results` header
   (RFC 8601) a message already carries for its SPF/DKIM/DMARC
   verdicts, plus whether a `DKIM-Signature` header is present at all.
4. **Sender anomaly** (`undercover.anomaly` via the API) -- from Phase 4.
   `undercover-risk` calls `GET /anomaly/senders` and checks whether
   this message's sender is in the flagged list.

Each signal is optional -- `undercover.risk.scoring.assess_risk()`
accepts all four as optional arguments and computes a **weighted
average over whichever are actually supplied**, rather than assuming
every signal ran. A message that was only ever DLP-scanned still gets
a sensible risk score; it isn't penalized for signals that were never
computed. This is the same graceful-degradation philosophy used
throughout the project for missing *dependencies* (spaCy, scikit-learn,
httpx), applied here to missing *signals* instead.

## Why header validation is header *parsing*, not live verification

Real SPF/DKIM/DMARC verification requires DNS lookups (SPF, DMARC
policy) and, for DKIM, cryptographically verifying a signature against
the exact canonicalized bytes the sending server signed. Both need
information this tool doesn't have when analyzing a `.eml` file after
the fact: the actual connecting SMTP client IP (SPF is verified against
whoever connected to *your* mail server, which we aren't), and the
original unmodified message bytes.

What every major mail provider does instead -- and what
`undercover.risk.headers` does -- is read the `Authentication-Results`
header the *receiving* mail server already added after doing that
verification (RFC 8601). This is a legitimate, standard approach (it's
literally where Gmail's and Outlook's own phishing warnings get their
SPF/DKIM/DMARC status from), but it means the result is only as
trustworthy as the mail server that added the header: a message
crafted to include a fake `Authentication-Results` header claiming
`spf=pass` would be taken at face value unless it arrived through a
boundary that strips forged instances of the header before adding its
own (a standard MTA practice, not something this tool does).

## Risk levels

| risk_score | risk_level |
|-----------|------------|
| >= 0.80    | critical   |
| >= 0.60    | high       |
| >= 0.30    | medium     |
| < 0.30     | low        |

Weights (relative, when all four signals are present): phishing 0.45,
DLP 0.25, header auth 0.20, sender anomaly 0.10. Like Phase 2's verdict
thresholds and Phase 4's `contamination`, these are reasonable starting
points, not calibrated against real labeled outcomes.

## SIEM export: CEF and JSON

```bash
undercover-risk --format json suspect_email.eml
undercover-risk --format cef suspect_email.eml
```

CEF (Common Event Format) is what most SIEMs -- ArcSight, Splunk,
QRadar -- ingest natively:

```
CEF:0|undercover|SecurityScanner|0.1.0|risk-assessment|Email risk assessment|9|fname=suspect_email.eml suser=attacker@evil.example cs1Label=RiskLevel cs1=critical cn1Label=FactorCount cn1=3 msg=phishing verdict: phishing; DMARC authentication failed
```

Severity (0-10) is `risk_score * 10`, rounded. The `msg` field carries
the human-readable reason from each contributing factor, joined with
`;` -- this is what a SOC analyst actually reads first. Field values
are escaped per the CEF spec: `|` and `\` in the pipe-delimited header
fields, `=` and `\` in the space-delimited extension values (pipes
don't need escaping there -- the extension delimiter is a space, not a
pipe, which is a common point of confusion the tests in
`tests/risk/test_export.py` check explicitly).

## Persisting assessments

`undercover-risk --submit` posts to `POST /risk/assessments`
(`undercover.api.routes.risk`), stored in `RiskAssessment`/`RiskFactor`
tables mirroring the `PhishingAnalysis`/`PhishingRuleHit` pattern from
Phase 3. `GET /risk/assessments` and `GET /risk/assessments/{id}` list
and retrieve them, same shape as the other phases' routes.

## Testing

```bash
pip install -e ".[dev]"                       # headers, scoring, export, CLI (rules-only)
pip install -e ".[dev,api,phishing,anomaly]"  # + the /risk/assessments route, ML, anomaly check
pytest tests/risk tests/api/test_risk_routes.py
```

`test_scoring.py` checks that missing signals don't artificially drag
the score down (a message scored on phishing alone maxes out the same
as one where every signal maxes out), that the weighted average lands
where expected, and each risk-level threshold boundary.
`test_headers.py` covers the pass/fail/inconclusive/no-header cases
against hand-built `Authentication-Results` values.
`test_export.py` verifies CEF's two different escaping rules (header
vs. extension fields) don't get conflated -- an earlier draft of this
test asserted the wrong one and would have shipped a false "bug" in
review; fixed after checking the CEF spec.

## Known limitations

- **Header authentication trusts the message's own claimed
  `Authentication-Results` header** -- see "Why header validation is
  header parsing" above. Fine when analyzing mail that already passed
  through a real mail security boundary; not a substitute for actually
  being that boundary.
- **The anomaly-sender check is a snapshot, not a guarantee.** A
  first-time sender with no prior submissions can't be flagged
  anomalous yet (Phase 4 needs history to compare against), so
  `undercover-risk` reports "sender has no prior submissions on
  record" rather than treating an unknown sender as either safe or
  suspicious.
- **Weights and thresholds are unvalidated heuristics**, the same
  caveat as every scoring decision in Phases 2 and 4.
- **No first-class "message" entity ties a DLP scan, phishing
  analysis, and risk assessment together in storage** -- each is
  submitted and stored independently, linked only loosely by matching
  `source`/`sender_email` strings, not a shared foreign key. A
  dashboard wanting "show me everything known about this one email"
  would need to join on those fields today rather than a single ID.

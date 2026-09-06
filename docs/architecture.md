# Architecture

## Current shape (Phases 1-2)

```
src/undercover/
├── cli.py              # Phase 1 entry point: `undercover` (DLP scan)
├── dlp/
│   ├── patterns.py     # regex rules + validators (Luhn, SSN checksum, IP)
│   ├── ner.py           # optional spaCy wrapper, lazy-loaded
│   └── scanner.py       # DLPScanner: orchestrates regex + NER into Findings
├── phishing/
│   ├── email_message.py # EmailMessage.from_raw: parses headers/body/links
│   ├── rules.py          # RuleEngine: urgency language, spoofed names, etc.
│   ├── classifier.py     # optional scikit-learn TF-IDF + LogisticRegression
│   ├── detector.py        # PhishingDetector: blends rules + ML into a verdict
│   ├── cli.py              # entry point: `undercover-phish`
│   └── train_cli.py        # entry point: `undercover-phish-train`
├── api/                  # Phase 3 stub
├── anomaly/              # Phase 4 stub
└── risk/                 # Phase 5 stub
```

### Design decisions

- **Regex and NER are independent passes.** `DLPScanner` always runs
  the regex pass (fast, dependency-free, deterministic) and only
  attempts NER if `use_ner=True` and spaCy plus a language model are
  actually installed. If NER can't run, the scanner degrades to
  regex-only and reports why via `ScanResult.ner_skip_reason` rather
  than raising -- the CLI should never hard-fail just because an
  optional dependency is missing.
- **Validators reject shape-only matches.** A regex alone can't tell a
  real SSN from three groups of digits that happen to look like one,
  or a real credit card number from a random 16-digit string. Each
  `PatternRule` may carry a `validator` (Luhn checksum for card
  numbers, area/group/serial range checks for SSNs, octet range checks
  for IPv4) that runs against the raw regex match before it becomes a
  `Finding`. These are still heuristics, not proof of validity.
- **Findings never carry raw sensitive values downstream.**
  `Finding.to_dict()` (and the CLI's human-readable output) always go
  through `Finding.redacted()`, which masks everything but the last 4
  characters. The full `Finding.value` field stays in-process for
  callers that explicitly need it (e.g. a future encrypted case-store)
  but is never the thing printed or serialized by default.
- **The same optional-dependency pattern repeats for Phase 2's
  classifier.** `PhishingClassifier` treats scikit-learn exactly like
  `dlp.ner` treats spaCy: `is_available()`/`load_error()` checked
  lazily, `PhishingDetector.analyze()` never raises just because it's
  missing, and the caller gets a `ml_skip_reason` string instead.
  Rules and ML are independent passes for the same reason regex and
  NER are in Phase 1 -- a missing optional dependency should degrade
  the signal, not break the tool.
- **Rule hits are weighted and summed, not boolean.** Rather than a
  single "is this phishing" rule, `RuleEngine` collects every hit
  (`RuleHit(name, description, weight)`) so `PhishingResult.rule_hits`
  is explainable -- a human reviewing a verdict can see exactly which
  signals fired and why, which matters for a security tool people are
  expected to trust.

## Where later phases plug in

- **Phase 2 (phishing)** sits alongside `dlp/` as its own package,
  operating on `EmailMessage` (parsed headers + body) rather than raw
  DLP `Finding`s -- the two scanners look at the same email for
  different things and don't share state today. Phase 5's risk-scoring
  layer is where their outputs actually get combined.
- **Phase 3 (API)** turns the CLI from a fire-and-forget tool into a
  client: `undercover scan` will optionally POST results to a FastAPI
  backend instead of (or in addition to) printing them, with SQLite as
  the initial datastore.
- **Phase 4 (anomaly)** consumes the metadata the API has accumulated
  (sender, timing, volume) rather than single-message content, so it
  naturally depends on Phase 3 existing first.
- **Phase 5 (risk scoring)** is a fusion layer: it reads DLP findings,
  phishing scores, anomaly scores, and header-auth results for a
  message and produces one number plus a CEF/JSON export.

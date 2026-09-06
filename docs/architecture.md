# Architecture

## Current shape (Phases 1-5, all core phases implemented, plus attachment scanning, alerting, and MITRE ATT&CK tagging)

```
src/undercover/
├── cli.py              # Phase 1 entry point: `undercover` (DLP scan)
├── mitre.py             # ATT&CK technique registry + RuleHit-name -> technique mapping
├── dlp/
│   ├── patterns.py     # regex rules + validators (Luhn, SSN checksum, IP)
│   ├── ner.py           # optional spaCy wrapper, lazy-loaded
│   └── scanner.py       # DLPScanner: orchestrates regex + NER into Findings
├── phishing/
│   ├── email_message.py # EmailMessage.from_raw: parses headers/body/links/attachments
│   ├── rules.py          # RuleEngine: urgency language, spoofed names, etc.
│   ├── classifier.py     # optional scikit-learn TF-IDF + LogisticRegression
│   ├── detector.py        # PhishingDetector: blends rules + ML into a verdict
│   ├── cli.py              # entry point: `undercover-phish`
│   └── train_cli.py        # entry point: `undercover-phish-train`
├── api/
│   ├── client.py          # ApiClient: httpx-only, used by --submit in every CLI
│   ├── database.py         # SQLAlchemy engine/session, SQLite by default
│   ├── models.py            # DlpScan/Finding, PhishingAnalysis/RuleHit, RiskAssessment/Factor
│   ├── schemas.py            # Pydantic request/response shapes
│   ├── routes/                 # /dlp/scans, /phishing/analyses, /anomaly/senders, /risk/assessments
│   ├── server.py               # FastAPI app (create_app, lifespan -> init_db)
│   └── serve_cli.py             # entry point: `undercover-api`
├── anomaly/
│   ├── features.py        # extract_sender_features: groups analyses by sender
│   ├── detector.py         # optional scikit-learn IsolationForest
│   └── cli.py                # entry point: `undercover-anomaly` (thin API client)
├── attachments/
│   ├── virustotal.py       # hash-only lookup against VirusTotal's public API v3
│   ├── malwarebazaar.py     # hash-only lookup against abuse.ch's MalwareBazaar
│   └── scanner.py            # AttachmentScanner combines both; summarize_attachment_risk
├── alerting/
│   ├── channels.py         # WebhookChannel, SlackChannel -- both optional-httpx
│   ├── manager.py           # AlertManager: threshold logic, fan-out to channels
│   └── alert.py               # Alert dataclass + build_alert (structural typing, see below)
└── risk/
    ├── headers.py          # Authentication-Results (SPF/DKIM/DMARC) parsing
    ├── scoring.py           # assess_risk: fuses DLP+phishing+header+anomaly+attachment signals
    ├── export.py             # to_json / to_cef (SIEM export)
    └── cli.py                 # entry point: `undercover-risk` (runs everything on one email)
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
- **The API client is intentionally thin and separately importable.**
  `undercover.api.client.ApiClient` needs only `httpx`; the server
  side (`server.py`, `models.py`, `routes/`) needs the full `api`
  extra (fastapi, sqlalchemy, uvicorn). `undercover/api/__init__.py`
  only re-exports the client, so `undercover --submit` and
  `undercover-phish --submit` don't force the server stack onto every
  user -- same optional-dependency philosophy as NER and the ML
  classifier, just applied to a network call instead of a model.
- **DLP and phishing results get their own narrow tables**
  (`DlpScan`/`DlpFinding`, `PhishingAnalysis`/`PhishingRuleHit`) rather
  than one polymorphic "finding" table, because their shapes genuinely
  differ (character offsets vs. rule weights) and forcing them
  together would mean a discriminator column and nullable fields for
  whichever type doesn't apply.
- **Anomaly detection operates on senders, not messages.** Phases 1-2
  already score individual messages; scoring messages again with
  `IsolationForest` would just be a worse classifier. `AnomalyDetector`
  instead aggregates every stored `PhishingAnalysis` per
  `sender_email` (`undercover.anomaly.features.extract_sender_features`)
  and looks for senders whose aggregate behavior -- volume, average/max
  risk score, phishing ratio, send-time regularity -- doesn't fit the
  rest of the batch. It's a read-only computed view (`GET
  /anomaly/senders`), not something a client submits to.
- **`sender_email` was added to `PhishingAnalysis` specifically to
  enable this.** It wasn't needed until Phase 4 needed a join key to
  group analyses by sender; adding it to the existing model/schema/
  client was a small, additive change rather than a redesign.
- **Every risk signal in Phase 5 is optional, and missing signals don't
  drag the score down.** `assess_risk()` takes DLP/phishing/header/
  anomaly inputs as `Optional` and computes a weighted average over
  only the signals actually supplied (normalizing by their combined
  weight) rather than treating a missing signal as zero. A message
  scored on phishing alone maxes out identically to one where every
  signal maxes out -- the same graceful-degradation principle used for
  missing *dependencies* elsewhere in the project, applied here to
  missing *signals*.
- **Header authentication is parsed, not independently verified.**
  `undercover.risk.headers` reads the `Authentication-Results` header
  a message already carries (RFC 8601) rather than performing DNS
  lookups or DKIM cryptographic verification itself -- doing either
  properly requires information (the true connecting SMTP IP, the
  exact canonicalized original bytes) this tool doesn't have when
  analyzing a `.eml` file after the fact. This is the same approach
  Gmail's and Outlook's own phishing warnings use internally.
- **DLP's contribution to the risk score uses noisy-OR, not a linear
  scale.** `1 - ∏(1 - confidence_i)` over all findings is "the
  probability at least one finding is real," treating each finding as
  independent evidence, rather than an arbitrary `count * weight`
  formula that would need its own separate justification for the
  scaling constant.
- **MITRE ATT&CK tags are computed, not stored.** A rule hit's
  technique(s) are a deterministic function of its `name`
  (`undercover.mitre.techniques_for_rule_hit`), so `RuleHit` exposes
  them as a `@property` and `PhishingRuleHit` (the ORM model) mirrors
  that with its own `@property` -- the same computed-field pattern
  `DlpScan.finding_count` already used, extended to a lookup instead of
  a `len()`. Only phishing `RuleHit`s are tagged: DLP findings describe
  message *content*, not adversary *behavior*, so there's no honest
  ATT&CK mapping for them, and forcing one would overclaim what the
  tool's signals actually represent.
- **Alerting is centralized in the API, not duplicated per CLI.**
  `POST /risk/assessments` calls `AlertManager().maybe_alert()` on
  every submission regardless of source, so a future dashboard or
  scheduled job that submits assessments gets alerting for free without
  reimplementing it. `undercover-risk --alert-threshold` is a separate,
  standalone path for using alerting without the API at all; passing
  both `--submit` and `--alert-threshold` skips the standalone one
  rather than double-alerting.
- **`build_alert()` takes a `Protocol`, not a concrete class.** The API
  route builds an alert from the incoming Pydantic
  `RiskAssessmentCreate` payload; the CLI's standalone path builds one
  from the `undercover.risk.scoring.RiskAssessment` dataclass. Both
  satisfy the same structural shape (`risk_level`, `risk_score`,
  `factors`) without `undercover.alerting` needing to import either
  `undercover.api.schemas` or `undercover.risk.scoring` -- the same
  reason `undercover.api.client` avoids importing the server modules.
- **An alerting failure can never break a submission.** The
  `RiskAssessment` row is already committed by the time
  `AlertManager` runs in the route handler; any exception from it is
  caught and logged, not allowed to turn a successful submission into
  a 500. Caught by writing the test for this, not by anticipating it
  up front -- see docs/alerting.md's Design Decisions for how.
- **Attachment scanning is hash-lookup-only, and opt-in.** VirusTotal
  and MalwareBazaar both support uploading a file; `undercover.attachments`
  only ever sends a SHA-256 already computed locally (privacy, and it
  matches what a fast CLI triage step should do -- not run a malware
  sandbox). It's also the one risk signal that isn't automatic: every
  other factor in `assess_risk()` is either local or a read against
  data this project already collected, but attachment scanning makes a
  real third-party network call, so `undercover-risk` only does it when
  `--check-attachments` is passed explicitly.

## Where later phases plug in

- **Phase 2 (phishing)** sits alongside `dlp/` as its own package,
  operating on `EmailMessage` (parsed headers + body) rather than raw
  DLP `Finding`s -- the two scanners look at the same email for
  different things and don't share state today. Phase 5's risk-scoring
  layer is where their outputs actually get combined.
- **Phase 3 (API)** turned the CLIs from fire-and-forget tools into
  clients: `undercover --submit` and `undercover-phish --submit` POST
  results to the FastAPI backend instead of (or in addition to)
  printing them, with SQLite as the initial datastore (swappable for
  Postgres via `UNDERCOVER_DB_URL`, no code change).
- **Phase 4 (anomaly)** consumes the metadata the API has accumulated
  (sender, timing, volume) rather than single-message content, which is
  why it depended on Phase 3 existing first -- and why it needed one
  small addition to Phase 3's schema (`PhishingAnalysis.sender_email`)
  to have a join key at all.
- **Phase 5 (risk scoring)** is the fusion layer the earlier phases were
  building toward: `undercover-risk` runs the Phase 1 DLP scanner and
  Phase 2 phishing detector locally, parses headers itself, checks
  Phase 4's anomaly report over the API, and produces one risk score
  plus a CEF/JSON export -- the single command a SOC analyst would
  actually run against a suspicious email, rather than four separate
  tools they'd have to reconcile by hand.

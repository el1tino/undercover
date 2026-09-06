# Alerting

The second "later addition": a high or critical risk assessment
previously just sat in the database until someone thought to look.
This adds a notification the moment one is created.

## What it does

`undercover.alerting.AlertManager` checks a risk level against a
threshold (default `high`, or `$UNDERCOVER_ALERT_THRESHOLD`) and, if
crossed, sends the alert through every configured channel:

- **`WebhookChannel`** -- POSTs a generic JSON payload
  (`title`, `message`, `risk_level`, `risk_score`, `source`,
  `sender_email`) to `$UNDERCOVER_ALERT_WEBHOOK_URL`.
- **`SlackChannel`** -- POSTs a formatted message to a Slack incoming
  webhook URL (`$UNDERCOVER_SLACK_WEBHOOK_URL`), with a severity emoji
  and the same fields folded into readable text.

Either, both, or neither can be configured. An unconfigured channel
returns an `AlertResult` explaining why (missing URL, missing httpx)
rather than raising -- the same graceful-degradation pattern used for
every other optional integration in this project.

## Where it fires

**`POST /risk/assessments`** (Phase 3's API) calls
`AlertManager().maybe_alert()` on every submission, regardless of
which client submitted it. This is deliberately centralized: any
CLI invocation, a future scheduled job, or a dashboard hitting the API
directly all go through the same alerting path, rather than each
client needing its own alerting logic. A failure in alert delivery is
caught and logged there -- it can never break the submission itself,
since the assessment is already committed to the database by the time
alerting runs.

**`undercover-risk --alert-threshold LEVEL`** is the standalone path,
for using the alerting system without the API at all. Passing both
`--submit` and `--alert-threshold` skips the standalone path with a
note (`--submit` already covers it via the API) rather than delivering
the same alert twice.

## Setup

```bash
pip install -e ".[alerting]"   # or [api] -- both just need httpx

export UNDERCOVER_ALERT_WEBHOOK_URL="https://example.com/your-webhook"
export UNDERCOVER_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export UNDERCOVER_ALERT_THRESHOLD="high"   # optional, this is the default
```

## Usage

```bash
# Via the API (fires automatically on every submission that crosses the threshold)
undercover-risk --submit suspect_email.eml

# Standalone, no API involved
undercover-risk --alert-threshold high suspect_email.eml
```

Slack message example:

> :rotating_light: **CRITICAL risk email detected**
> phishing verdict: phishing; DMARC authentication failed
> Risk: **CRITICAL** (0.87) -- source: `suspect_email.eml` -- sender: `attacker@evil.example`

## Design decisions

- **Alerting lives in the API, not just the CLI.** A CLI-only design
  would mean every tool that submits a risk assessment needs to
  re-implement alerting, and a submission from anywhere other than
  `undercover-risk` (a future scheduled job, a dashboard) would never
  alert at all. Centralizing it in `POST /risk/assessments` means the
  alert fires based on what's actually stored, regardless of source.
- **`build_alert()` takes a structural type (`Protocol`), not a
  concrete class.** The API route builds an alert directly from the
  incoming `RiskAssessmentCreate` Pydantic payload (before it's even
  written to the database), while `undercover-risk`'s standalone path
  builds one from `undercover.risk.scoring.RiskAssessment` (a
  dataclass). Both satisfy the same `risk_level`/`risk_score`/`factors`
  shape without either needing to import the other -- the API doesn't
  need to depend on `undercover.risk`, and `undercover.risk` doesn't
  need to depend on the API's schemas.
- **An alerting failure is caught and logged, never allowed to break a
  submission.** The assessment is already committed by the time
  `AlertManager` runs; a broken webhook URL or an unexpected exception
  in a channel must not turn a successful submission into a 500. This
  was caught while writing
  `tests/api/test_risk_routes.py::TestAlertingIntegration` -- an
  earlier version let alerting exceptions propagate, which the test
  initially encoded as expected behavior before being fixed to
  actually assert graceful handling instead.

## Testing

```bash
pip install -e ".[dev,alerting]"           # channels + manager + alert building
pip install -e ".[dev,api,alerting]"       # + the API route wiring
pytest tests/alerting tests/api/test_risk_routes.py::TestAlertingIntegration
```

Channel tests never make real network calls -- `httpx.post` is always
monkeypatched, split into skip-if-httpx-missing/present classes like
every other optional-dependency test in this project. The API
integration test monkeypatches `undercover.api.routes.risk.AlertManager`
itself (the name as imported into that module) rather than configuring
real webhook URLs, so it verifies the route calls `AlertManager` with a
correctly-built `Alert` without needing any network access.

## Known limitations

- **No delivery retry or backoff.** A transient failure (Slack rate
  limiting, a flaky webhook endpoint) is reported once and dropped --
  there's no queue or retry mechanism.
- **No alert history.** Unlike `RiskAssessment` itself, whether an
  alert was actually delivered isn't persisted anywhere; it's only
  printed to stderr (CLI) or logged (API). A real case-management
  system (a later roadmap item) would want to track this.
- **Only two channels.** Email (SMTP) and PagerDuty/OpsGenie-style
  paging integrations are common in real SOC alerting and aren't
  implemented -- `AlertManager` accepts any object with a `.send()`
  method, so adding one is mostly writing that one class.

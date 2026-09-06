# Phase 2: Phishing Detection

## What it does

`undercover.phishing.PhishingDetector` analyzes a parsed email and
produces a verdict (`clean` / `suspicious` / `phishing`) by combining
two independent signals:

1. **Rule-based heuristics** (`undercover.phishing.rules`), always on,
   no dependencies:
   - **Urgency language** -- phrases like "verify your account",
     "act now", "your account will be closed".
   - **Generic greetings** -- "Dear Valued Customer" instead of a name.
   - **Suspicious links** -- links to a raw IP address, known URL
     shorteners, high-abuse TLDs (`.top`, `.zip`, `.xyz`, ...), and
     (for HTML mail) anchor text that names one domain while the
     `href` points at another.
   - **Spoofed display names** -- a display name referencing a known
     brand (PayPal, Amazon, Microsoft, IRS, ...) whose sender domain
     doesn't actually belong to that brand.
   - **Sender / Reply-To mismatch** -- the `From` and `Reply-To`
     headers point at different domains.

   Each hit carries a weight; hit weights sum into a 0-1 rule score
   (capped at 1.0).

2. **An optional ML classifier** (`undercover.phishing.classifier`),
   a scikit-learn `TfidfVectorizer` + `LogisticRegression` pipeline
   trained on labeled phishing/ham text, predicting P(phishing) for
   the subject+body. Like `undercover.dlp.ner`'s spaCy dependency,
   this degrades gracefully: if scikit-learn isn't installed, the
   detector just skips it and says why via `ml_skip_reason`, instead
   of raising.

`PhishingDetector.analyze()` blends the two 50/50 when the ML score is
available (`rule_score` alone otherwise) into `combined_score`, then
maps that to a verdict:

| combined_score | verdict      |
|----------------|--------------|
| >= 0.70         | `phishing`   |
| >= 0.35         | `suspicious` |
| < 0.35          | `clean`      |

These weights and thresholds are heuristic starting points, not
calibrated against a real labeled corpus -- see **Known limitations**
below.

## The bundled dataset is a toy

`src/undercover/phishing/data/sample_dataset.csv` has 50 short,
synthetic examples (25 phishing, 25 ham) so the classifier has
*something* to train on out of the box with zero setup. It is **not**
a real training corpus -- it's too small and too clean to generalize.
For real use, swap in something like:

- [Kaggle's Phishing Email Dataset](https://www.kaggle.com/datasets/subhajournal/phishingemails)
- The [Nazario phishing corpus](https://monkey.org/~jose/phishing/)
- Your own labeled mail, exported as `text,label` CSV with
  `label` in `{"phishing", "ham"}`.

Then retrain and persist a real model:

```bash
pip install -e ".[phishing]"
undercover-phish-train --dataset path/to/real_dataset.csv --out models/phishing_classifier.joblib
undercover-phish --model models/phishing_classifier.joblib suspect_email.eml
```

Without `--model`, `undercover-phish` trains the demo pipeline
in-memory on the bundled dataset on every run -- fine for trying the
tool out, not for production (retraining on 50 rows each invocation
is fast, but a real dataset would not be).

## CLI usage

```bash
# Analyze a .eml file (or plaintext headers+body)
undercover-phish path/to/email.eml

# Analyze stdin
cat email.eml | undercover-phish

# Machine-readable output
undercover-phish --json path/to/email.eml

# Rules only, skip the ML classifier
undercover-phish --no-ml path/to/email.eml

# Use a pre-trained model instead of retraining on the demo dataset
undercover-phish --model models/phishing_classifier.joblib path/to/email.eml

# Exit 1 if the verdict isn't "clean" (CI / pre-commit)
undercover-phish --fail-on-detect path/to/email.eml
```

`undercover-phish-train` trains and saves a model:

```bash
undercover-phish-train --dataset data.csv --out models/phishing_classifier.joblib
```

## Why a separate entry point from `undercover`

Phase 1 shipped `undercover` as the DLP-scanning command. Rather than
retrofit subcommands into that CLI (and risk changing its existing
argument contract), Phase 2 ships as its own entry points
(`undercover-phish`, `undercover-phish-train`), mirroring how the
`dlp` and `phishing` packages are independent modules. Phase 3's API
server is a natural point to unify these into one consistent surface
(a single client submitting both DLP and phishing findings), so this
is expected to consolidate rather than multiply further.

## Testing

```bash
pip install -e ".[dev]"          # rule engine + degraded-classifier tests
pip install -e ".[dev,phishing]" # + real training/prediction tests
pytest tests/phishing
```

The classifier tests are split into an "unavailable" class (runs when
scikit-learn isn't installed, asserts the skip-reason path) and an
"available" class (runs when it is, and actually trains + predicts),
using `pytest.mark.skipif` so the suite is green either way -- the
same pattern used for the DLP module's spaCy dependency.

## Known limitations

- **Toy dataset.** See above -- 50 synthetic rows will not generalize
  to real phishing campaigns. Treat `ml_score` as a demonstration of
  the pipeline, not a production-grade signal, until retrained on a
  real corpus.
- **Brand list is illustrative, not exhaustive.** `rules.BRAND_DOMAINS`
  covers about a dozen commonly-spoofed brands; anything outside that
  list won't trigger the spoofed-display-name check.
- **No SPF/DKIM/DMARC validation yet.** Header authentication is
  Phase 5's job; this phase only looks at `From`/`Reply-To` header
  *consistency*, not cryptographic proof of sender identity.
- **Thresholds are unvalidated.** The 0.35/0.70 verdict cutoffs and
  the 50/50 rule/ML blend are reasonable starting points, not the
  output of an ROC analysis against real data.

# Phase 4: Anomaly Detection

## What it does

Phases 1-2 catch things a rule or a trained classifier already knows
to look for. Phase 4 catches something else: a sender whose *pattern
of behavior* doesn't fit, even if no single message they sent tripped
a rule. It does this with an `IsolationForest` over per-sender
aggregate statistics computed from the phishing analyses Phase 3 has
already stored -- which is why it depends on Phase 3 existing first.

```
GET /anomaly/senders?contamination=0.2
```

or from the CLI:

```bash
undercover-anomaly
```

## How it works

1. **`undercover.anomaly.features.extract_sender_features`** groups
   every stored `PhishingAnalysis` row by `sender_email` (rows with no
   sender are dropped -- there's nothing to attribute them to) and
   computes, per sender:
   - `message_count` -- how many analyses this sender has on record
   - `avg_combined_score` / `max_combined_score` -- how risky their
     messages scored, on average and at worst
   - `phishing_ratio` / `suspicious_ratio` -- fraction of their
     messages that landed in each verdict bucket
   - `send_hour_stddev` -- spread of the hour-of-day their messages
     were submitted at (a very low spread across many messages can
     indicate scripted/bot-like sending; a real analysis would also
     want day-of-week and inter-arrival time, left for later)

2. **`undercover.anomaly.detector.AnomalyDetector`** fits a scikit-learn
   `IsolationForest` over the resulting feature vectors and flags
   senders that don't fit with the rest of the batch. It's an optional
   dependency (`pip install undercover[anomaly]`) following the same
   `is_available()`/`load_error()` pattern as `dlp.ner` and
   `phishing.classifier` -- if scikit-learn isn't installed, or there
   are fewer than `MIN_SENDERS` (3) distinct senders to compare, the
   report comes back with `skip_reason` set and an empty `results`
   list instead of raising.

3. **`GET /anomaly/senders`** (in `undercover.api.routes.anomaly`) ties
   the two together: query stored analyses, extract features, run the
   detector, return the report. There's no POST for this resource --
   it's a computed view over existing data, not something a client
   submits.

## Why per-sender, not per-message

Phases 1-2 already score individual messages. An anomaly detector
doing the same thing per-message would just be a worse version of the
phishing classifier. What it can add is a dimension neither rules nor
a single-message classifier see: *this sender specifically* looks
different from the rest -- unusually high volume, an unusually high
phishing rate among their messages, unusually regular timing. That's
inherently a property of a sender's history, not any one message, so
the unit of analysis here is the sender, aggregated over everything
they've submitted so far.

## Why `sender_email` needed to be added to Phase 3's schema

`PhishingAnalysis` originally only stored `source` (the file path or
`<stdin>` label passed to the CLI) -- there was no join key to group
analyses by sender. Phase 4 needed one, so `sender_email` was added to
`PhishingAnalysis`, its schemas, `ApiClient.submit_phishing_analysis`,
and the `undercover-phish --submit` path (which now passes
`msg.sender_email` alongside the detection result). This is a
deliberately small, additive schema change -- it doesn't touch
`PhishingResult.to_dict()` itself, since sender identity is metadata
about the submission, not part of the phishing detection result.

## Interpreting the output

```json
{
  "results": [
    {
      "sender_email": "attacker@evil.example",
      "is_anomaly": true,
      "anomaly_score": 0.31,
      "message_count": 30,
      "avg_combined_score": 0.95,
      "max_combined_score": 1.0,
      "phishing_ratio": 1.0,
      "suspicious_ratio": 0.0,
      "send_hour_stddev": 0.0
    }
  ],
  "skip_reason": null
}
```

`anomaly_score` is `IsolationForest`'s decision function, inverted so
**higher means more anomalous** (the raw scikit-learn convention is the
opposite -- higher means more normal -- which reads backwards for a
security tool, so this module flips the sign before returning it).
`is_anomaly` is `IsolationForest`'s own `predict() == -1`, driven by
the `contamination` parameter (expected fraction of outliers in the
batch); `anomaly_score` is the more useful field for ranking when you
want to see "how anomalous" rather than a bare yes/no.

## Known limitations

- **Outlier-relative-to-the-batch, not outlier-relative-to-normal.**
  `IsolationForest` here has no fixed notion of "typical" mail
  behavior -- it only knows what's unusual *among the senders
  currently in the database*. A deployment with only phishing senders
  and no legitimate traffic would flag the wrong ones as outliers.
  This is fine for demonstrating the technique; a real system would
  want to train on a large baseline of known-legitimate sender
  behavior and score new senders against that baseline instead of
  re-fitting on every request.
- **`contamination` and `MIN_SENDERS` are unvalidated heuristics**,
  same caveat as Phase 2's verdict thresholds -- reasonable starting
  points, not the output of tuning against real labeled abuse data.
- **Features are coarse.** No relationship-graph features yet (who a
  sender emails, whether that's a new relationship), no day-of-week or
  inter-arrival timing, no volume-over-time trend (a sudden spike vs. a
  steady high volume look identical to `message_count` alone). The
  roadmap's "relationship graphs" piece is still open.
- **Refit-on-every-request.** `/anomaly/senders` re-trains the
  `IsolationForest` from scratch on each call rather than persisting a
  fitted model. Fine at demo scale (fitting on a few dozen-to-hundreds
  of senders is fast); a production version would fit periodically and
  score incrementally.

## Testing

```bash
pip install -e ".[dev,anomaly]"      # feature/detector unit tests
pip install -e ".[dev,api,anomaly]"  # + the /anomaly/senders route test
pytest tests/anomaly tests/api/test_anomaly_routes.py
```

`test_detector.py` follows the same skip-if-unavailable /
skip-if-available split as Phase 2's classifier tests, and includes a
synthetic-outlier test: several senders with similar, low-risk
aggregate stats plus one sender with high volume, high average score,
and a high phishing ratio -- the detector should rank that one first
and flag it. The route test does the same thing end-to-end through the
API, submitting real `PhishingAnalysisCreate` payloads first.

"""Unit tests for undercover.anomaly.detector.AnomalyDetector.

Split the same way tests/phishing/test_classifier.py handles the
optional scikit-learn dependency: one path for it missing (always
runs, asserts the skip-reason), one for it installed (only runs with
the `anomaly`/`phishing` extra, trains and predicts for real).
"""

import pytest

from undercover.anomaly.detector import MIN_SENDERS, AnomalyDetector, is_available
from undercover.anomaly.features import SenderFeatures


def make_features(sender_email, **overrides):
    defaults = dict(
        message_count=3,
        avg_combined_score=0.15,
        max_combined_score=0.25,
        phishing_ratio=0.0,
        suspicious_ratio=0.0,
        send_hour_stddev=2.0,
    )
    defaults.update(overrides)
    return SenderFeatures(sender_email=sender_email, **defaults)


NORMAL_SENDERS = [
    make_features("alice@acme.com"),
    make_features("bob@acme.com", message_count=2, avg_combined_score=0.1),
    make_features("carol@acme.com", message_count=4, avg_combined_score=0.2),
    make_features("dave@acme.com", message_count=3, avg_combined_score=0.12),
]

OUTLIER_SENDER = make_features(
    "attacker@evil-domain.example",
    message_count=60,
    avg_combined_score=0.95,
    max_combined_score=1.0,
    phishing_ratio=0.9,
    suspicious_ratio=0.1,
    send_hour_stddev=0.0,
)


@pytest.mark.skipif(is_available(), reason="scikit-learn is installed")
class TestUnavailable:
    def test_reports_skip_reason(self):
        report = AnomalyDetector().detect(NORMAL_SENDERS + [OUTLIER_SENDER])
        assert report.results == []
        assert report.skip_reason is not None


@pytest.mark.skipif(not is_available(), reason="scikit-learn is not installed")
class TestAvailable:
    def test_flags_the_obvious_outlier(self):
        report = AnomalyDetector(contamination=0.2).detect(
            NORMAL_SENDERS + [OUTLIER_SENDER]
        )
        assert report.skip_reason is None
        outlier_result = next(
            r
            for r in report.results
            if r.sender_email == "attacker@evil-domain.example"
        )
        assert outlier_result.is_anomaly is True
        # the outlier should have the highest anomaly score of the batch
        assert report.results[0].sender_email == "attacker@evil-domain.example"

    def test_results_sorted_by_score_descending(self):
        report = AnomalyDetector().detect(NORMAL_SENDERS + [OUTLIER_SENDER])
        scores = [r.anomaly_score for r in report.results]
        assert scores == sorted(scores, reverse=True)

    def test_too_few_senders_skips_with_reason(self):
        report = AnomalyDetector().detect(NORMAL_SENDERS[:2])
        assert report.results == []
        assert str(MIN_SENDERS) in report.skip_reason

    def test_all_similar_senders_flags_nothing_or_little(self):
        similar = [
            make_features(f"user{i}@acme.com", message_count=3 + (i % 2))
            for i in range(5)
        ]
        report = AnomalyDetector(contamination=0.1).detect(similar)
        assert report.skip_reason is None
        # With near-identical senders, IsolationForest shouldn't be
        # confident enough to flag most of them.
        anomalous = [r for r in report.results if r.is_anomaly]
        assert len(anomalous) <= 1

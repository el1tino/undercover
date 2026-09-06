"""Unit tests for undercover.anomaly.features.extract_sender_features."""

from datetime import datetime

from undercover.anomaly.features import extract_sender_features


def record(sender, verdict, score, hour=9, day=1):
    return {
        "sender_email": sender,
        "verdict": verdict,
        "combined_score": score,
        "created_at": datetime(2026, 1, day, hour, 0, 0),
    }


class TestGrouping:
    def test_groups_by_sender(self):
        records = [
            record("a@x.com", "clean", 0.1),
            record("a@x.com", "clean", 0.2),
            record("b@x.com", "phishing", 0.9),
        ]
        features = extract_sender_features(records)
        senders = {f.sender_email for f in features}
        assert senders == {"a@x.com", "b@x.com"}

    def test_drops_records_without_sender(self):
        records = [
            record(None, "clean", 0.1),
            record("", "clean", 0.1),
            record("a@x.com", "clean", 0.1),
        ]
        features = extract_sender_features(records)
        assert len(features) == 1
        assert features[0].sender_email == "a@x.com"

    def test_empty_input_returns_empty_list(self):
        assert extract_sender_features([]) == []


class TestAggregation:
    def test_message_count(self):
        records = [record("a@x.com", "clean", 0.1) for _ in range(4)]
        features = extract_sender_features(records)
        assert features[0].message_count == 4

    def test_avg_and_max_combined_score(self):
        records = [
            record("a@x.com", "clean", 0.2),
            record("a@x.com", "phishing", 0.8),
        ]
        features = extract_sender_features(records)
        f = features[0]
        assert f.avg_combined_score == 0.5
        assert f.max_combined_score == 0.8

    def test_phishing_and_suspicious_ratios(self):
        records = [
            record("a@x.com", "phishing", 0.9),
            record("a@x.com", "phishing", 0.9),
            record("a@x.com", "suspicious", 0.5),
            record("a@x.com", "clean", 0.1),
        ]
        features = extract_sender_features(records)
        f = features[0]
        assert f.phishing_ratio == 0.5
        assert f.suspicious_ratio == 0.25

    def test_single_message_has_zero_stddev(self):
        records = [record("a@x.com", "clean", 0.1, hour=14)]
        features = extract_sender_features(records)
        assert features[0].send_hour_stddev == 0.0

    def test_varied_hours_have_nonzero_stddev(self):
        records = [
            record("a@x.com", "clean", 0.1, hour=2, day=1),
            record("a@x.com", "clean", 0.1, hour=14, day=2),
            record("a@x.com", "clean", 0.1, hour=23, day=3),
        ]
        features = extract_sender_features(records)
        assert features[0].send_hour_stddev > 0.0

    def test_to_vector_length_and_order(self):
        records = [record("a@x.com", "phishing", 0.7)]
        f = extract_sender_features(records)[0]
        vector = f.to_vector()
        assert len(vector) == 6
        assert vector[0] == 1.0  # message_count

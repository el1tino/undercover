"""Anomaly detection (Phase 4).

Aggregates per-sender features from submitted phishing analyses
(undercover.anomaly.features) and flags outlier senders with an
optional scikit-learn IsolationForest (undercover.anomaly.detector).
Exposed via the API at GET /anomaly/senders and the `undercover-anomaly`
CLI. See docs/phase4-anomaly-detection.md and docs/roadmap.md.
"""

from undercover.anomaly.detector import AnomalyDetector, AnomalyReport, AnomalyResult
from undercover.anomaly.features import SenderFeatures, extract_sender_features

__all__ = [
    "AnomalyDetector",
    "AnomalyReport",
    "AnomalyResult",
    "SenderFeatures",
    "extract_sender_features",
]

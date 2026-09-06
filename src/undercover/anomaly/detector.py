"""Optional scikit-learn IsolationForest over per-sender aggregate features.

scikit-learn is an optional dependency (the `anomaly` extra:
`pip install undercover[anomaly]`), following the same
is_available()/load_error() pattern as undercover.dlp.ner and
undercover.phishing.classifier: a missing dependency degrades the
result (via AnomalyReport.skip_reason) rather than raising.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from undercover.anomaly.features import SenderFeatures

# IsolationForest run on 1-2 points is meaningless (there's no "normal" to
# be an outlier from); this is a floor for the report to be worth trusting.
MIN_SENDERS = 3

_load_error: Optional[str] = None
_import_checked = False


def is_available() -> bool:
    return _check_import() is None


def load_error() -> Optional[str]:
    return _check_import()


def _check_import() -> Optional[str]:
    global _load_error, _import_checked
    if _import_checked:
        return _load_error
    _import_checked = True
    try:
        import sklearn  # noqa: F401
    except ImportError:
        _load_error = (
            "scikit-learn is not installed. Install it with "
            "`pip install undercover[anomaly]`."
        )
    return _load_error


@dataclass(frozen=True)
class AnomalyResult:
    sender_email: str
    is_anomaly: bool
    anomaly_score: float  # higher = more anomalous
    features: SenderFeatures


@dataclass(frozen=True)
class AnomalyReport:
    results: list[AnomalyResult]
    skip_reason: Optional[str] = None


class AnomalyDetector:
    """Flags senders whose aggregate behavior is an outlier among the rest.

    This looks for outliers *relative to the other senders in the same
    batch* -- it has no fixed notion of "normal" and needs a reasonable
    number of senders to be meaningful (see MIN_SENDERS). `contamination`
    is IsolationForest's expected fraction of outliers; the default 0.2
    is a starting point, not a calibrated value -- see
    docs/phase4-anomaly-detection.md.
    """

    def __init__(self, contamination: float = 0.2, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state

    def detect(self, features: list[SenderFeatures]) -> AnomalyReport:
        if not is_available():
            return AnomalyReport(results=[], skip_reason=load_error())

        if len(features) < MIN_SENDERS:
            return AnomalyReport(
                results=[],
                skip_reason=(
                    f"Need at least {MIN_SENDERS} distinct senders with "
                    f"submitted analyses to run anomaly detection "
                    f"(found {len(features)})."
                ),
            )

        from sklearn.ensemble import IsolationForest

        matrix = [f.to_vector() for f in features]
        model = IsolationForest(
            contamination=self.contamination, random_state=self.random_state
        )
        model.fit(matrix)
        raw_scores = model.decision_function(matrix)  # higher = more normal
        predictions = model.predict(matrix)  # -1 = anomaly, 1 = normal

        results = [
            AnomalyResult(
                sender_email=feat.sender_email,
                is_anomaly=bool(pred == -1),
                anomaly_score=float(-score),
                features=feat,
            )
            for feat, score, pred in zip(features, raw_scores, predictions)
        ]
        results.sort(key=lambda r: r.anomaly_score, reverse=True)
        return AnomalyReport(results=results, skip_reason=None)

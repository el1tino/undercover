"""Aggregates per-sender features from stored phishing analyses.

Phase 4 needs something to detect anomalies *in* -- here, that's each
sender's history of submitted phishing analyses (Phase 2's output,
persisted by Phase 3): how many messages they've sent, how risky those
messages scored, and how regular their sending times are.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from statistics import pstdev
from typing import Iterable, TypedDict


class AnalysisRecord(TypedDict):
    sender_email: str | None
    verdict: str
    combined_score: float
    created_at: datetime


@dataclass(frozen=True)
class SenderFeatures:
    """Aggregate statistics for one sender's submitted phishing analyses."""

    sender_email: str
    message_count: int
    avg_combined_score: float
    max_combined_score: float
    phishing_ratio: float
    suspicious_ratio: float
    send_hour_stddev: float

    def to_vector(self) -> list[float]:
        return [
            float(self.message_count),
            self.avg_combined_score,
            self.max_combined_score,
            self.phishing_ratio,
            self.suspicious_ratio,
            self.send_hour_stddev,
        ]


def extract_sender_features(records: Iterable[AnalysisRecord]) -> list[SenderFeatures]:
    """Group analysis records by sender_email and compute aggregate features.

    Records with no sender_email are dropped -- there's nothing to
    attribute them to. A malformed `From` header can leave Phase 2's
    EmailMessage.sender_email empty, and Phase 1 DLP scans don't carry
    a sender at all.
    """
    by_sender: dict[str, list[AnalysisRecord]] = {}
    for record in records:
        sender = record.get("sender_email")
        if not sender:
            continue
        by_sender.setdefault(sender, []).append(record)

    features: list[SenderFeatures] = []
    for sender, sender_records in by_sender.items():
        scores = [r["combined_score"] for r in sender_records]
        verdicts = [r["verdict"] for r in sender_records]
        hours = [r["created_at"].hour for r in sender_records]
        count = len(sender_records)
        features.append(
            SenderFeatures(
                sender_email=sender,
                message_count=count,
                avg_combined_score=sum(scores) / count,
                max_combined_score=max(scores),
                phishing_ratio=verdicts.count("phishing") / count,
                suspicious_ratio=verdicts.count("suspicious") / count,
                send_hour_stddev=pstdev(hours) if count > 1 else 0.0,
            )
        )
    return features

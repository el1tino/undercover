"""Combines the rule engine and the ML classifier into one phishing verdict."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from undercover.phishing.classifier import PhishingClassifier
from undercover.phishing.email_message import EmailMessage
from undercover.phishing.rules import RuleEngine, RuleHit

# Rules and the ML classifier are weighted equally: rules catch what's
# obvious and explainable, the classifier catches phrasing/structure that
# doesn't match any single rule. Thresholds are heuristic starting points,
# not calibrated against a real labeled corpus -- see docs/phase2-phishing-detection.md.
RULE_WEIGHT = 0.5
ML_WEIGHT = 0.5
PHISHING_THRESHOLD = 0.7
SUSPICIOUS_THRESHOLD = 0.35


@dataclass
class PhishingResult:
    rule_hits: list[RuleHit]
    rule_score: float
    ml_score: Optional[float]
    ml_skip_reason: Optional[str]
    combined_score: float
    verdict: str  # "clean" | "suspicious" | "phishing"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "combined_score": round(self.combined_score, 4),
            "rule_score": round(self.rule_score, 4),
            "ml_score": round(self.ml_score, 4) if self.ml_score is not None else None,
            "ml_skip_reason": self.ml_skip_reason,
            "rule_hits": [
                {
                    "name": h.name,
                    "description": h.description,
                    "weight": h.weight,
                    "mitre_techniques": [
                        {"id": t.id, "name": t.name, "url": t.url}
                        for t in h.mitre_techniques
                    ],
                }
                for h in self.rule_hits
            ],
        }


def _verdict_for(score: float) -> str:
    if score >= PHISHING_THRESHOLD:
        return "phishing"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


class PhishingDetector:
    """Runs the rule engine, and optionally the ML classifier, on a message."""

    def __init__(self, use_ml: bool = True, model_path: Optional[Path] = None):
        self.rule_engine = RuleEngine()
        self.classifier = PhishingClassifier(model_path=model_path) if use_ml else None

    def analyze(self, msg: EmailMessage) -> PhishingResult:
        evaluation = self.rule_engine.evaluate(msg)

        ml_score: Optional[float] = None
        ml_skip_reason: Optional[str] = None
        if self.classifier is not None:
            if self.classifier.is_ready():
                ml_score = self.classifier.predict_proba(msg.full_text)
            else:
                ml_skip_reason = self.classifier.skip_reason()

        if ml_score is not None:
            combined = RULE_WEIGHT * evaluation.score + ML_WEIGHT * ml_score
        else:
            combined = evaluation.score

        return PhishingResult(
            rule_hits=evaluation.hits,
            rule_score=evaluation.score,
            ml_score=ml_score,
            ml_skip_reason=ml_skip_reason,
            combined_score=combined,
            verdict=_verdict_for(combined),
        )

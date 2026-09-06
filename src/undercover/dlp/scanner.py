"""DLP scanner: finds structured PII/secrets (regex) and unstructured PII (NER)."""

from __future__ import annotations

from dataclasses import dataclass, field

from undercover.dlp import ner
from undercover.dlp.patterns import PATTERNS


@dataclass
class Finding:
    """A single piece of sensitive data located in scanned text."""

    type: str
    label: str
    value: str
    start: int
    end: int
    source: str  # "regex" or "ner"
    confidence: float

    def redacted(self) -> str:
        """Return the matched value with all but the last 4 characters masked."""
        if len(self.value) <= 4:
            return "*" * len(self.value)
        return "*" * (len(self.value) - 4) + self.value[-4:]

    def to_dict(self) -> dict:
        d = {
            "type": self.type,
            "label": self.label,
            "value": self.redacted(),
            "start": self.start,
            "end": self.end,
            "source": self.source,
            "confidence": self.confidence,
        }
        return d


@dataclass
class ScanResult:
    """The outcome of scanning one piece of text."""

    findings: list[Finding] = field(default_factory=list)
    ner_ran: bool = False
    ner_skip_reason: str | None = None

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def by_type(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.type, []).append(finding)
        return grouped

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "ner_ran": self.ner_ran,
            "ner_skip_reason": self.ner_skip_reason,
        }


class DLPScanner:
    """Scans text for sensitive data using regex rules and optional NER."""

    def __init__(self, use_ner: bool = True):
        self.use_ner = use_ner

    def scan(self, text: str) -> ScanResult:
        findings: list[Finding] = list(self._scan_regex(text))

        ner_ran = False
        ner_skip_reason = None
        if self.use_ner:
            if ner.is_available():
                findings.extend(self._scan_ner(text))
                ner_ran = True
            else:
                ner_skip_reason = ner.load_error()

        findings.sort(key=lambda f: f.start)
        return ScanResult(
            findings=findings, ner_ran=ner_ran, ner_skip_reason=ner_skip_reason
        )

    def _scan_regex(self, text: str):
        for rule in PATTERNS:
            for match in rule.regex.finditer(text):
                if rule.validator is not None and not rule.validator(match):
                    continue
                yield Finding(
                    type=rule.name,
                    label=rule.label,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    source="regex",
                    confidence=rule.confidence,
                )

    def _scan_ner(self, text: str):
        for entity in ner.find_entities(text):
            yield Finding(
                type=entity["name"],
                label=entity["label"],
                value=entity["value"],
                start=entity["start"],
                end=entity["end"],
                source="ner",
                confidence=0.7,
            )

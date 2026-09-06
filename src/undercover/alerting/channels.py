"""Alert delivery channels: a generic JSON webhook and a Slack incoming
webhook. httpx is optional (the `alerting` extra); both channels degrade
gracefully -- an unconfigured or dependency-missing channel returns an
AlertResult explaining why rather than raising, following the same
pattern as every other optional dependency in this project.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from undercover.alerting._httpx_support import is_available, load_error
from undercover.alerting.alert import Alert

_SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":large_orange_diamond:",
    "low": ":white_check_mark:",
}


@dataclass(frozen=True)
class AlertResult:
    channel: str
    attempted: bool  # True if a delivery attempt was actually made
    delivered: bool
    detail: str


class WebhookChannel:
    """POSTs a generic JSON payload to a configured URL."""

    def __init__(self, url: Optional[str] = None, timeout: float = 10.0):
        self.url = url or os.environ.get("UNDERCOVER_ALERT_WEBHOOK_URL")
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.url)

    def send(self, alert: Alert) -> AlertResult:
        if not is_available():
            return AlertResult("webhook", False, False, load_error())
        if not self.is_configured():
            return AlertResult(
                "webhook", False, False,
                "no webhook URL configured (set UNDERCOVER_ALERT_WEBHOOK_URL)",
            )

        import httpx

        payload = {
            "title": alert.title,
            "message": alert.message,
            "risk_level": alert.risk_level,
            "risk_score": alert.risk_score,
            "source": alert.source,
            "sender_email": alert.sender_email,
        }
        try:
            response = httpx.post(self.url, json=payload, timeout=self.timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return AlertResult("webhook", True, False, f"webhook delivery failed: {exc}")
        return AlertResult(
            "webhook", True, True, f"delivered (HTTP {response.status_code})"
        )


class SlackChannel:
    """POSTs a formatted message to a Slack incoming webhook."""

    def __init__(self, url: Optional[str] = None, timeout: float = 10.0):
        self.url = url or os.environ.get("UNDERCOVER_SLACK_WEBHOOK_URL")
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.url)

    def _format_text(self, alert: Alert) -> str:
        emoji = _SEVERITY_EMOJI.get(alert.risk_level, "")
        text = (
            f"{emoji} *{alert.title}*\n{alert.message}\n"
            f"Risk: *{alert.risk_level.upper()}* ({alert.risk_score:.2f}) "
            f"-- source: `{alert.source}`"
        )
        if alert.sender_email:
            text += f" -- sender: `{alert.sender_email}`"
        return text

    def send(self, alert: Alert) -> AlertResult:
        if not is_available():
            return AlertResult("slack", False, False, load_error())
        if not self.is_configured():
            return AlertResult(
                "slack", False, False,
                "no Slack webhook URL configured (set UNDERCOVER_SLACK_WEBHOOK_URL)",
            )

        import httpx

        try:
            response = httpx.post(
                self.url, json={"text": self._format_text(alert)}, timeout=self.timeout
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return AlertResult("slack", True, False, f"Slack delivery failed: {exc}")
        return AlertResult("slack", True, True, "delivered to Slack")

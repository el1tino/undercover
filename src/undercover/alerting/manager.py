"""AlertManager: decides whether a risk level crosses the alert
threshold and, if so, sends it through every configured channel."""

from __future__ import annotations

import os
from typing import Optional

from undercover.alerting.alert import Alert
from undercover.alerting.channels import AlertResult, SlackChannel, WebhookChannel

LEVEL_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
DEFAULT_THRESHOLD_ENV = "UNDERCOVER_ALERT_THRESHOLD"
DEFAULT_THRESHOLD = "high"


class AlertManager:
    def __init__(self, channels: Optional[list] = None, threshold: Optional[str] = None):
        self.channels = channels if channels is not None else [WebhookChannel(), SlackChannel()]
        self.threshold = threshold or os.environ.get(
            DEFAULT_THRESHOLD_ENV, DEFAULT_THRESHOLD
        )

    def should_alert(self, risk_level: str) -> bool:
        return LEVEL_ORDER.get(risk_level, 0) >= LEVEL_ORDER.get(self.threshold, 2)

    def maybe_alert(self, alert: Alert) -> Optional[list[AlertResult]]:
        """Sends `alert` through every channel if its risk_level is at or
        above the threshold; returns None (no attempt made) otherwise."""
        if not self.should_alert(alert.risk_level):
            return None
        return [channel.send(alert) for channel in self.channels]

"""Alerting: notify a webhook or Slack when a risk assessment crosses
a threshold, instead of it just sitting in the database.

AlertManager.maybe_alert() is the entry point -- it checks the
assessment's risk_level against a threshold (default "high", or
$UNDERCOVER_ALERT_THRESHOLD) and, if crossed, sends the alert through
every configured channel (undercover.alerting.channels.WebhookChannel,
SlackChannel). Wired into POST /risk/assessments (so any submission,
regardless of source, triggers a centralized alert) and available
standalone via `undercover-risk --alert-threshold`. See
docs/alerting.md and docs/roadmap.md.
"""

from undercover.alerting.alert import Alert, build_alert
from undercover.alerting.channels import AlertResult, SlackChannel, WebhookChannel
from undercover.alerting.manager import AlertManager

__all__ = [
    "Alert",
    "build_alert",
    "AlertResult",
    "SlackChannel",
    "WebhookChannel",
    "AlertManager",
]

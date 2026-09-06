"""Unit tests for undercover.alerting.manager.AlertManager."""

from undercover.alerting.alert import Alert
from undercover.alerting.channels import AlertResult
from undercover.alerting.manager import AlertManager


def make_alert(risk_level="high") -> Alert:
    return Alert(
        title="test alert",
        message="test message",
        risk_level=risk_level,
        risk_score=0.7,
        source="test.eml",
    )


class FakeChannel:
    def __init__(self, name="fake", delivered=True):
        self.name = name
        self.delivered = delivered
        self.calls = []

    def send(self, alert: Alert) -> AlertResult:
        self.calls.append(alert)
        return AlertResult(self.name, True, self.delivered, "ok")


class TestShouldAlert:
    def test_below_threshold_is_false(self):
        manager = AlertManager(threshold="high")
        assert manager.should_alert("medium") is False
        assert manager.should_alert("low") is False

    def test_at_or_above_threshold_is_true(self):
        manager = AlertManager(threshold="high")
        assert manager.should_alert("high") is True
        assert manager.should_alert("critical") is True

    def test_default_threshold_is_high(self, monkeypatch):
        monkeypatch.delenv("UNDERCOVER_ALERT_THRESHOLD", raising=False)
        manager = AlertManager(channels=[])
        assert manager.threshold == "high"

    def test_threshold_from_env_var(self, monkeypatch):
        monkeypatch.setenv("UNDERCOVER_ALERT_THRESHOLD", "medium")
        manager = AlertManager(channels=[])
        assert manager.threshold == "medium"

    def test_explicit_threshold_overrides_env(self, monkeypatch):
        monkeypatch.setenv("UNDERCOVER_ALERT_THRESHOLD", "medium")
        manager = AlertManager(channels=[], threshold="critical")
        assert manager.threshold == "critical"


class TestMaybeAlert:
    def test_returns_none_below_threshold(self):
        channel = FakeChannel()
        manager = AlertManager(channels=[channel], threshold="critical")
        result = manager.maybe_alert(make_alert(risk_level="high"))
        assert result is None
        assert channel.calls == []

    def test_sends_to_all_channels_at_threshold(self):
        webhook = FakeChannel(name="webhook")
        slack = FakeChannel(name="slack")
        manager = AlertManager(channels=[webhook, slack], threshold="high")
        results = manager.maybe_alert(make_alert(risk_level="high"))

        assert len(webhook.calls) == 1
        assert len(slack.calls) == 1
        assert len(results) == 2
        assert {r.channel for r in results} == {"webhook", "slack"}

    def test_sends_when_above_threshold(self):
        channel = FakeChannel()
        manager = AlertManager(channels=[channel], threshold="medium")
        manager.maybe_alert(make_alert(risk_level="critical"))
        assert len(channel.calls) == 1

    def test_partial_delivery_failure_reported_per_channel(self):
        good = FakeChannel(name="webhook", delivered=True)
        bad = FakeChannel(name="slack", delivered=False)
        manager = AlertManager(channels=[good, bad], threshold="high")
        results = manager.maybe_alert(make_alert(risk_level="high"))
        by_channel = {r.channel: r.delivered for r in results}
        assert by_channel == {"webhook": True, "slack": False}

"""Unit tests for WebhookChannel and SlackChannel.

Split the same way tests/phishing/test_classifier.py handles scikit-learn:
one path for httpx missing, one for httpx present -- and within the
"present" path, httpx.post is always monkeypatched with a crafted
response, never a real network call.
"""

import pytest

from undercover.alerting._httpx_support import is_available
from undercover.alerting.alert import Alert
from undercover.alerting.channels import SlackChannel, WebhookChannel


def make_alert(**overrides) -> Alert:
    defaults = dict(
        title="HIGH risk email detected",
        message="phishing verdict: phishing",
        risk_level="high",
        risk_score=0.75,
        source="phishing.eml",
        sender_email="attacker@evil.example",
    )
    defaults.update(overrides)
    return Alert(**defaults)


@pytest.mark.skipif(is_available(), reason="httpx is installed")
class TestUnavailable:
    def test_webhook_not_attempted(self):
        result = WebhookChannel(url="https://example.test/hook").send(make_alert())
        assert result.attempted is False
        assert "not installed" in result.detail

    def test_slack_not_attempted(self):
        result = SlackChannel(url="https://hooks.slack.com/x").send(make_alert())
        assert result.attempted is False


@pytest.mark.skipif(not is_available(), reason="httpx is not installed")
class TestWebhookChannel:
    def test_not_configured_without_url(self, monkeypatch):
        monkeypatch.delenv("UNDERCOVER_ALERT_WEBHOOK_URL", raising=False)
        channel = WebhookChannel()
        assert channel.is_configured() is False
        result = channel.send(make_alert())
        assert result.attempted is False
        assert "no webhook URL configured" in result.detail

    def test_configured_via_env_var(self, monkeypatch):
        monkeypatch.setenv("UNDERCOVER_ALERT_WEBHOOK_URL", "https://example.test/hook")
        channel = WebhookChannel()
        assert channel.is_configured() is True

    def test_successful_delivery(self, monkeypatch):
        import httpx

        captured = {}

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

        def fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResponse()

        monkeypatch.setattr(httpx, "post", fake_post)
        channel = WebhookChannel(url="https://example.test/hook")
        result = channel.send(make_alert())

        assert result.attempted is True
        assert result.delivered is True
        assert captured["url"] == "https://example.test/hook"
        assert captured["json"]["risk_level"] == "high"
        assert captured["json"]["sender_email"] == "attacker@evil.example"

    def test_delivery_failure(self, monkeypatch):
        import httpx

        def fake_post(url, json=None, timeout=None):
            raise httpx.ConnectError("boom", request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx, "post", fake_post)
        result = WebhookChannel(url="https://example.test/hook").send(make_alert())
        assert result.attempted is True
        assert result.delivered is False
        assert "failed" in result.detail

    def test_http_error_status_marks_undelivered(self, monkeypatch):
        import httpx

        class FakeResponse:
            status_code = 500

            def raise_for_status(self):
                raise httpx.HTTPStatusError(
                    "500", request=httpx.Request("POST", "https://x"), response=self
                )

        monkeypatch.setattr(httpx, "post", lambda *a, **kw: FakeResponse())
        result = WebhookChannel(url="https://example.test/hook").send(make_alert())
        assert result.delivered is False


@pytest.mark.skipif(not is_available(), reason="httpx is not installed")
class TestSlackChannel:
    def test_not_configured_without_url(self, monkeypatch):
        monkeypatch.delenv("UNDERCOVER_SLACK_WEBHOOK_URL", raising=False)
        channel = SlackChannel()
        assert channel.is_configured() is False
        result = channel.send(make_alert())
        assert result.attempted is False

    def test_successful_delivery_formats_text(self, monkeypatch):
        import httpx

        captured = {}

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

        def fake_post(url, json=None, timeout=None):
            captured["json"] = json
            return FakeResponse()

        monkeypatch.setattr(httpx, "post", fake_post)
        channel = SlackChannel(url="https://hooks.slack.com/x")
        result = channel.send(make_alert(risk_level="critical"))

        assert result.attempted is True
        assert result.delivered is True
        assert "text" in captured["json"]
        assert "CRITICAL" in captured["json"]["text"]
        assert "attacker@evil.example" in captured["json"]["text"]

    def test_message_without_sender_omits_sender_line(self, monkeypatch):
        import httpx

        captured = {}

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

        def fake_post(url, json=None, timeout=None):
            captured["json"] = json
            return FakeResponse()

        monkeypatch.setattr(httpx, "post", fake_post)
        SlackChannel(url="https://hooks.slack.com/x").send(
            make_alert(sender_email=None)
        )
        assert "sender:" not in captured["json"]["text"]

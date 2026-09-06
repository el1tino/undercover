"""Unit tests for undercover.api.client, the CLI-side submission client.

Split the same way tests/phishing/test_classifier.py handles scikit-learn:
one path for httpx missing (always runs), one for httpx present (only
runs when the `api` extra is installed).
"""

import pytest

from undercover.api import client as client_module
from undercover.api.client import ApiClient, ApiClientError, is_available


class DummyResult:
    def to_dict(self) -> dict:
        return {"findings": [], "ner_ran": False, "ner_skip_reason": None}


@pytest.mark.skipif(is_available(), reason="httpx is installed")
class TestUnavailable:
    def test_submit_raises_with_reason(self):
        api_client = ApiClient()
        with pytest.raises(ApiClientError):
            api_client.submit_dlp_scan("file.txt", DummyResult())


@pytest.mark.skipif(not is_available(), reason="httpx is not installed")
class TestAvailable:
    def test_submit_dlp_scan_posts_expected_payload(self, monkeypatch):
        import httpx

        captured = {}

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"id": 1}

        def fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResponse()

        monkeypatch.setattr(httpx, "post", fake_post)

        api_client = ApiClient(base_url="http://example.test")
        result = api_client.submit_dlp_scan("file.txt", DummyResult())

        assert result == {"id": 1}
        assert captured["url"] == "http://example.test/dlp/scans"
        assert captured["json"]["source"] == "file.txt"
        assert captured["json"]["findings"] == []

    def test_submit_phishing_analysis_posts_to_correct_path(self, monkeypatch):
        import httpx

        captured = {}

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"id": 7}

        def fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResponse()

        monkeypatch.setattr(httpx, "post", fake_post)

        class DummyPhishingResult:
            def to_dict(self) -> dict:
                return {"verdict": "clean", "combined_score": 0.0, "rule_score": 0.0}

        api_client = ApiClient(base_url="http://example.test")
        api_client.submit_phishing_analysis(
            "mail.eml", DummyPhishingResult(), sender_email="jane@example.com"
        )
        assert captured["url"] == "http://example.test/phishing/analyses"
        assert captured["json"]["sender_email"] == "jane@example.com"

    def test_get_sender_anomalies_uses_get_with_params(self, monkeypatch):
        import httpx

        captured = {}

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"results": [], "skip_reason": None}

        def fake_get(url, params=None, timeout=None):
            captured["url"] = url
            captured["params"] = params
            return FakeResponse()

        monkeypatch.setattr(httpx, "get", fake_get)

        api_client = ApiClient(base_url="http://example.test")
        result = api_client.get_sender_anomalies(contamination=0.3)
        assert result == {"results": [], "skip_reason": None}
        assert captured["url"] == "http://example.test/anomaly/senders"
        assert captured["params"] == {"contamination": 0.3}

    def test_submit_risk_assessment_posts_expected_payload(self, monkeypatch):
        import httpx

        captured = {}

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"id": 3}

        def fake_post(url, json=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResponse()

        monkeypatch.setattr(httpx, "post", fake_post)

        class DummyAssessment:
            def to_dict(self) -> dict:
                return {"risk_score": 0.5, "risk_level": "medium", "factors": []}

        api_client = ApiClient(base_url="http://example.test")
        result = api_client.submit_risk_assessment(
            "mail.eml", DummyAssessment(), sender_email="jane@example.com"
        )
        assert result == {"id": 3}
        assert captured["url"] == "http://example.test/risk/assessments"
        assert captured["json"]["sender_email"] == "jane@example.com"
        assert captured["json"]["risk_level"] == "medium"

    def test_connection_error_raises_api_client_error(self, monkeypatch):
        import httpx

        def fake_post(url, json=None, timeout=None):
            raise httpx.ConnectError("boom", request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx, "post", fake_post)

        api_client = ApiClient()
        with pytest.raises(ApiClientError):
            api_client.submit_dlp_scan("file.txt", DummyResult())

    def test_base_url_trailing_slash_is_stripped(self):
        api_client = ApiClient(base_url="http://example.test/")
        assert api_client.base_url == "http://example.test"

"""Unit tests for undercover.attachments.virustotal.VirusTotalClient.

Split the same way tests/phishing/test_classifier.py handles scikit-learn:
one path for httpx missing, one for httpx present -- and within the
"present" path, real network calls are never made; httpx.get is always
monkeypatched with a crafted response.
"""

import pytest

from undercover.attachments._httpx_support import is_available
from undercover.attachments.virustotal import VirusTotalClient

SHA256 = "a" * 64


@pytest.mark.skipif(is_available(), reason="httpx is installed")
class TestUnavailable:
    def test_returns_not_attempted(self):
        client = VirusTotalClient(api_key="fake-key")
        result = client.lookup_hash(SHA256)
        assert result.attempted is False
        assert "not installed" in result.detail


@pytest.mark.skipif(not is_available(), reason="httpx is not installed")
class TestNoApiKey:
    def test_not_configured_without_key(self, monkeypatch):
        monkeypatch.delenv("VT_API_KEY", raising=False)
        client = VirusTotalClient()
        assert client.is_configured() is False
        result = client.lookup_hash(SHA256)
        assert result.attempted is False
        assert "not configured" in result.detail

    def test_configured_via_env_var(self, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "env-key")
        client = VirusTotalClient()
        assert client.is_configured() is True
        assert client.api_key == "env-key"


@pytest.mark.skipif(not is_available(), reason="httpx is not installed")
class TestWithApiKey:
    def _client(self):
        return VirusTotalClient(api_key="fake-key")

    def test_malicious_hash(self, monkeypatch):
        import httpx

        class FakeResponse:
            status_code = 200

            def json(self):
                return {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 45,
                                "suspicious": 2,
                                "undetected": 20,
                                "harmless": 3,
                            }
                        }
                    }
                }

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: FakeResponse())
        result = self._client().lookup_hash(SHA256)
        assert result.attempted is True
        assert result.found is True
        assert result.malicious is True
        assert result.malicious_engines == 45
        assert result.total_engines == 70

    def test_clean_hash(self, monkeypatch):
        import httpx

        class FakeResponse:
            status_code = 200

            def json(self):
                return {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "undetected": 65,
                                "harmless": 5,
                            }
                        }
                    }
                }

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: FakeResponse())
        result = self._client().lookup_hash(SHA256)
        assert result.found is True
        assert result.malicious is False

    def test_hash_not_found(self, monkeypatch):
        import httpx

        class FakeResponse:
            status_code = 404

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: FakeResponse())
        result = self._client().lookup_hash(SHA256)
        assert result.attempted is True
        assert result.found is False
        assert result.malicious is False

    def test_server_error(self, monkeypatch):
        import httpx

        class FakeResponse:
            status_code = 500

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: FakeResponse())
        result = self._client().lookup_hash(SHA256)
        assert result.attempted is True
        assert result.found is False
        assert "500" in result.detail

    def test_network_error(self, monkeypatch):
        import httpx

        def raise_error(*args, **kwargs):
            raise httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))

        monkeypatch.setattr(httpx, "get", raise_error)
        result = self._client().lookup_hash(SHA256)
        assert result.attempted is True
        assert result.found is False
        assert result.malicious is False

    def test_sends_api_key_header(self, monkeypatch):
        import httpx

        captured = {}

        class FakeResponse:
            status_code = 404

        def fake_get(url, headers=None, timeout=None):
            captured["url"] = url
            captured["headers"] = headers
            return FakeResponse()

        monkeypatch.setattr(httpx, "get", fake_get)
        self._client().lookup_hash(SHA256)
        assert SHA256 in captured["url"]
        assert captured["headers"]["x-apikey"] == "fake-key"

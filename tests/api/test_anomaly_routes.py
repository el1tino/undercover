import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sklearn")


def _submit(client, sender_email, verdict, combined_score):
    client.post(
        "/phishing/analyses",
        json={
            "source": f"{sender_email}.eml",
            "sender_email": sender_email,
            "verdict": verdict,
            "combined_score": combined_score,
            "rule_score": combined_score,
            "rule_hits": [],
        },
    )


class TestSenderAnomalies:
    def test_skips_with_too_few_senders(self, client):
        _submit(client, "a@acme.com", "clean", 0.1)
        _submit(client, "b@acme.com", "clean", 0.1)

        resp = client.get("/anomaly/senders")
        assert resp.status_code == 200
        body = resp.json()
        assert body["results"] == []
        assert "senders" in body["skip_reason"]

    def test_flags_an_obvious_outlier(self, client):
        for name in ["a", "b", "c", "d"]:
            for _ in range(3):
                _submit(client, f"{name}@acme.com", "clean", 0.1)

        for _ in range(30):
            _submit(client, "attacker@evil.example", "phishing", 0.95)

        resp = client.get("/anomaly/senders", params={"contamination": 0.2})
        assert resp.status_code == 200
        body = resp.json()
        assert body["skip_reason"] is None

        by_sender = {row["sender_email"]: row for row in body["results"]}
        assert by_sender["attacker@evil.example"]["is_anomaly"] is True
        assert by_sender["attacker@evil.example"]["message_count"] == 30
        assert by_sender["attacker@evil.example"]["phishing_ratio"] == 1.0

    def test_ignores_analyses_with_no_sender(self, client):
        client.post(
            "/phishing/analyses",
            json={
                "source": "unknown.eml",
                "verdict": "clean",
                "combined_score": 0.0,
                "rule_score": 0.0,
                "rule_hits": [],
            },
        )
        _submit(client, "a@acme.com", "clean", 0.1)
        _submit(client, "b@acme.com", "clean", 0.1)

        resp = client.get("/anomaly/senders")
        # still only 2 distinct senders with an email -- below MIN_SENDERS
        assert resp.json()["results"] == []

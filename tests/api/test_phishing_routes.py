import pytest

pytest.importorskip("fastapi")


def _rule_hit(**overrides):
    hit = {
        "name": "urgency_language",
        "description": "Urgency phrase found: 'verify your account'",
        "weight": 0.15,
    }
    hit.update(overrides)
    return hit


class TestCreateAnalysis:
    def test_creates_analysis_with_rule_hits(self, client):
        payload = {
            "source": "phishing.eml",
            "verdict": "phishing",
            "combined_score": 0.87,
            "rule_score": 1.0,
            "ml_score": 0.74,
            "ml_skip_reason": None,
            "rule_hits": [_rule_hit()],
        }
        resp = client.post("/phishing/analyses", json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert body["verdict"] == "phishing"
        assert len(body["rule_hits"]) == 1

    def test_rule_hit_response_includes_mitre_techniques(self, client):
        payload = {
            "source": "phishing.eml",
            "verdict": "phishing",
            "combined_score": 0.87,
            "rule_score": 1.0,
            "rule_hits": [
                _rule_hit(name="urgency_language"),
                _rule_hit(name="generic_greeting", description="generic greeting"),
            ],
        }
        resp = client.post("/phishing/analyses", json=payload)
        body = resp.json()
        by_name = {h["name"]: h for h in body["rule_hits"]}
        assert by_name["urgency_language"]["mitre_techniques"] == [
            {
                "id": "T1566",
                "name": "Phishing",
                "url": "https://attack.mitre.org/techniques/T1566/",
            }
        ]
        assert by_name["generic_greeting"]["mitre_techniques"] == []

    def test_persists_sender_email(self, client):
        payload = {
            "source": "phishing.eml",
            "sender_email": "attacker@evil.example",
            "verdict": "phishing",
            "combined_score": 0.87,
            "rule_score": 1.0,
            "rule_hits": [],
        }
        resp = client.post("/phishing/analyses", json=payload)
        assert resp.status_code == 201
        assert resp.json()["sender_email"] == "attacker@evil.example"

    def test_sender_email_defaults_to_none(self, client):
        payload = {
            "source": "phishing.eml",
            "verdict": "phishing",
            "combined_score": 0.87,
            "rule_score": 1.0,
            "rule_hits": [],
        }
        resp = client.post("/phishing/analyses", json=payload)
        assert resp.json()["sender_email"] is None

    def test_creates_analysis_without_ml(self, client):
        payload = {
            "source": "clean.eml",
            "verdict": "clean",
            "combined_score": 0.0,
            "rule_score": 0.0,
            "ml_score": None,
            "ml_skip_reason": "scikit-learn is not installed.",
            "rule_hits": [],
        }
        resp = client.post("/phishing/analyses", json=payload)
        assert resp.status_code == 201
        assert resp.json()["ml_score"] is None


class TestListAnalyses:
    def test_returns_summaries_newest_first(self, client):
        client.post(
            "/phishing/analyses",
            json={
                "source": "clean.eml",
                "verdict": "clean",
                "combined_score": 0.1,
                "rule_score": 0.1,
                "rule_hits": [],
            },
        )
        client.post(
            "/phishing/analyses",
            json={
                "source": "phishing.eml",
                "verdict": "phishing",
                "combined_score": 0.9,
                "rule_score": 0.9,
                "rule_hits": [_rule_hit()],
            },
        )
        resp = client.get("/phishing/analyses")
        body = resp.json()
        assert len(body) == 2
        assert body[0]["source"] == "phishing.eml"


class TestGetAnalysis:
    def test_returns_full_detail(self, client):
        create_resp = client.post(
            "/phishing/analyses",
            json={
                "source": "phishing.eml",
                "verdict": "phishing",
                "combined_score": 0.9,
                "rule_score": 0.9,
                "rule_hits": [_rule_hit()],
            },
        )
        analysis_id = create_resp.json()["id"]

        resp = client.get(f"/phishing/analyses/{analysis_id}")
        assert resp.status_code == 200
        assert resp.json()["rule_hits"][0]["name"] == "urgency_language"

    def test_missing_analysis_returns_404(self, client):
        resp = client.get("/phishing/analyses/999999")
        assert resp.status_code == 404

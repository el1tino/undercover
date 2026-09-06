import pytest

pytest.importorskip("fastapi")


def _factor(**overrides):
    factor = {
        "name": "phishing",
        "weight": 0.45,
        "value": 0.9,
        "detail": "phishing verdict: phishing",
    }
    factor.update(overrides)
    return factor


class TestCreateAssessment:
    def test_creates_assessment_with_factors(self, client):
        payload = {
            "source": "phishing.eml",
            "sender_email": "attacker@evil.example",
            "risk_score": 0.87,
            "risk_level": "critical",
            "factors": [_factor()],
        }
        resp = client.post("/risk/assessments", json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert body["risk_level"] == "critical"
        assert body["sender_email"] == "attacker@evil.example"
        assert len(body["factors"]) == 1

    def test_creates_assessment_with_no_factors(self, client):
        payload = {
            "source": "clean.eml",
            "risk_score": 0.0,
            "risk_level": "low",
            "factors": [],
        }
        resp = client.post("/risk/assessments", json=payload)
        assert resp.status_code == 201
        assert resp.json()["factors"] == []
        assert resp.json()["sender_email"] is None


class TestListAssessments:
    def test_returns_summaries_newest_first(self, client):
        client.post(
            "/risk/assessments",
            json={"source": "a.eml", "risk_score": 0.1, "risk_level": "low", "factors": []},
        )
        client.post(
            "/risk/assessments",
            json={
                "source": "b.eml",
                "risk_score": 0.9,
                "risk_level": "critical",
                "factors": [_factor()],
            },
        )
        resp = client.get("/risk/assessments")
        body = resp.json()
        assert len(body) == 2
        assert body[0]["source"] == "b.eml"


class TestGetAssessment:
    def test_returns_full_detail(self, client):
        create_resp = client.post(
            "/risk/assessments",
            json={
                "source": "b.eml",
                "risk_score": 0.9,
                "risk_level": "critical",
                "factors": [_factor()],
            },
        )
        assessment_id = create_resp.json()["id"]

        resp = client.get(f"/risk/assessments/{assessment_id}")
        assert resp.status_code == 200
        assert resp.json()["factors"][0]["name"] == "phishing"

    def test_missing_assessment_returns_404(self, client):
        resp = client.get("/risk/assessments/999999")
        assert resp.status_code == 404

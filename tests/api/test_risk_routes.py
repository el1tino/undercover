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


class TestAlertingIntegration:
    def test_submission_calls_alert_manager_with_built_alert(self, client, monkeypatch):
        calls = []

        class FakeAlertManager:
            def __init__(self, *args, **kwargs):
                pass

            def maybe_alert(self, alert):
                calls.append(alert)
                return None

        monkeypatch.setattr(
            "undercover.api.risk_persistence.AlertManager", FakeAlertManager
        )

        resp = client.post(
            "/risk/assessments",
            json={
                "source": "phishing.eml",
                "sender_email": "attacker@evil.example",
                "risk_score": 0.9,
                "risk_level": "critical",
                "factors": [_factor()],
            },
        )
        assert resp.status_code == 201
        assert len(calls) == 1
        assert calls[0].risk_level == "critical"
        assert calls[0].source == "phishing.eml"
        assert calls[0].sender_email == "attacker@evil.example"

    def test_alert_manager_failure_does_not_break_submission(self, client, monkeypatch):
        # A misbehaving alert channel must never prevent the assessment
        # itself from being stored and returned -- the assessment is
        # already committed by the time alerting runs.
        class ExplodingAlertManager:
            def __init__(self, *args, **kwargs):
                pass

            def maybe_alert(self, alert):
                raise RuntimeError("simulated alerting failure")

        monkeypatch.setattr(
            "undercover.api.risk_persistence.AlertManager", ExplodingAlertManager
        )

        resp = client.post(
            "/risk/assessments",
            json={
                "source": "phishing.eml",
                "risk_score": 0.9,
                "risk_level": "critical",
                "factors": [],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["risk_level"] == "critical"


class TestStatusUpdate:
    def _create(self, client):
        resp = client.post(
            "/risk/assessments",
            json={"source": "a.eml", "risk_score": 0.9, "risk_level": "critical", "factors": []},
        )
        return resp.json()["id"]

    def test_new_assessment_defaults_to_open(self, client):
        assessment_id = self._create(client)
        resp = client.get(f"/risk/assessments/{assessment_id}")
        assert resp.json()["status"] == "open"

    def test_updates_status(self, client):
        assessment_id = self._create(client)
        resp = client.patch(
            f"/risk/assessments/{assessment_id}/status", json={"status": "investigating"}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

        # persisted, not just returned
        resp = client.get(f"/risk/assessments/{assessment_id}")
        assert resp.json()["status"] == "investigating"

    def test_rejects_invalid_status(self, client):
        assessment_id = self._create(client)
        resp = client.patch(
            f"/risk/assessments/{assessment_id}/status", json={"status": "not_a_real_status"}
        )
        assert resp.status_code == 422

    def test_missing_assessment_returns_404(self, client):
        resp = client.patch("/risk/assessments/999999/status", json={"status": "resolved"})
        assert resp.status_code == 404

    def test_status_change_creates_audit_entry(self, client):
        assessment_id = self._create(client)
        client.patch(f"/risk/assessments/{assessment_id}/status", json={"status": "resolved"})

        entries = client.get("/audit/log").json()
        status_change = next(
            e for e in entries if e["action"] == "risk_assessment.status_changed"
        )
        assert status_change["resource_id"] == assessment_id
        assert "'open' -> 'resolved'" in status_change["detail"]

    def test_list_filters_by_status(self, client):
        open_id = self._create(client)
        resolved_id = self._create(client)
        client.patch(f"/risk/assessments/{resolved_id}/status", json={"status": "resolved"})

        resp = client.get("/risk/assessments", params={"status": "open"})
        ids = [row["id"] for row in resp.json()]
        assert ids == [open_id]


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

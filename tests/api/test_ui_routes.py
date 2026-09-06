import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")


def _create_case(client, source="a.eml", risk_score=0.9, risk_level="critical"):
    resp = client.post(
        "/risk/assessments",
        json={"source": source, "risk_score": risk_score, "risk_level": risk_level, "factors": []},
    )
    return resp.json()["id"]


class TestCasesList:
    def test_empty_list_renders(self, client):
        resp = client.get("/ui/cases")
        assert resp.status_code == 200
        assert "No cases match" in resp.text

    def test_lists_created_case(self, client):
        _create_case(client, source="phishing.eml")
        resp = client.get("/ui/cases")
        assert "phishing.eml" in resp.text
        assert "critical" in resp.text

    def test_filters_by_status(self, client):
        open_id = _create_case(client, source="open.eml")
        resolved_id = _create_case(client, source="resolved.eml")
        client.patch(f"/risk/assessments/{resolved_id}/status", json={"status": "resolved"})

        resp = client.get("/ui/cases", params={"status": "open"})
        assert "open.eml" in resp.text
        assert "resolved.eml" not in resp.text

    def test_filters_by_risk_level(self, client):
        _create_case(client, source="low.eml", risk_score=0.1, risk_level="low")
        _create_case(client, source="crit.eml", risk_score=0.9, risk_level="critical")

        resp = client.get("/ui/cases", params={"risk_level": "critical"})
        assert "crit.eml" in resp.text
        assert "low.eml" not in resp.text


class TestCaseDetail:
    def test_renders_case_with_factors(self, client):
        resp = client.post(
            "/risk/assessments",
            json={
                "source": "phishing.eml",
                "sender_email": "attacker@evil.example",
                "risk_score": 0.9,
                "risk_level": "critical",
                "factors": [
                    {"name": "phishing", "weight": 0.4, "value": 1.0, "detail": "phishing verdict: phishing"}
                ],
            },
        )
        case_id = resp.json()["id"]

        detail = client.get(f"/ui/cases/{case_id}")
        assert detail.status_code == 200
        assert "attacker@evil.example" in detail.text
        assert "phishing verdict: phishing" in detail.text

    def test_missing_case_returns_404(self, client):
        resp = client.get("/ui/cases/999999")
        assert resp.status_code == 404

    def test_status_change_form_redirects_and_persists(self, client):
        case_id = _create_case(client)
        resp = client.post(
            f"/ui/cases/{case_id}/status", data={"status": "investigating"}, follow_redirects=False
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == f"/ui/cases/{case_id}"

        detail = client.get(f"/ui/cases/{case_id}")
        assert "investigating" in detail.text

    def test_status_change_creates_audit_entry(self, client):
        case_id = _create_case(client)
        client.post(f"/ui/cases/{case_id}/status", data={"status": "resolved"})

        entries = client.get("/audit/log").json()
        status_change = next(e for e in entries if e["action"] == "risk_assessment.status_changed")
        assert "via UI" in status_change["detail"]

    def test_status_change_rejects_invalid_status(self, client):
        case_id = _create_case(client)
        resp = client.post(f"/ui/cases/{case_id}/status", data={"status": "not_real"})
        assert resp.status_code == 400

    def test_status_change_missing_case_returns_404(self, client):
        resp = client.post("/ui/cases/999999/status", data={"status": "resolved"})
        assert resp.status_code == 404


class TestDashboard:
    def test_empty_dashboard_renders(self, client):
        resp = client.get("/ui/dashboard")
        assert resp.status_code == 200
        assert "0" in resp.text  # zero counts, but must not error

    def test_shows_verdict_and_risk_level_counts(self, client):
        client.post(
            "/phishing/analyses",
            json={
                "source": "a.eml",
                "verdict": "phishing",
                "combined_score": 0.9,
                "rule_score": 0.9,
                "rule_hits": [
                    {"name": "urgency_language", "description": "x", "weight": 0.15}
                ],
            },
        )
        _create_case(client)

        resp = client.get("/ui/dashboard")
        assert "phishing" in resp.text
        assert "critical" in resp.text

    def test_shows_mitre_technique_counts(self, client):
        client.post(
            "/phishing/analyses",
            json={
                "source": "a.eml",
                "verdict": "phishing",
                "combined_score": 0.9,
                "rule_score": 0.9,
                "rule_hits": [
                    {"name": "urgency_language", "description": "x", "weight": 0.15}
                ],
            },
        )
        resp = client.get("/ui/dashboard")
        assert "T1566" in resp.text
        assert "Phishing" in resp.text

    def test_shows_recent_cases(self, client):
        _create_case(client, source="recent.eml")
        resp = client.get("/ui/dashboard")
        assert "recent.eml" in resp.text

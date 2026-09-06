import pytest

pytest.importorskip("fastapi")


class TestAuditLogging:
    def test_dlp_scan_creates_audit_entry(self, client):
        resp = client.post(
            "/dlp/scans",
            json={"source": "email.txt", "findings": [], "ner_ran": False},
        )
        scan_id = resp.json()["id"]

        log_resp = client.get("/audit/log")
        assert log_resp.status_code == 200
        entries = log_resp.json()
        assert len(entries) == 1
        assert entries[0]["action"] == "dlp_scan.created"
        assert entries[0]["resource_type"] == "dlp_scan"
        assert entries[0]["resource_id"] == scan_id
        assert entries[0]["source_ip"] is not None

    def test_phishing_analysis_creates_audit_entry(self, client):
        resp = client.post(
            "/phishing/analyses",
            json={
                "source": "phishing.eml",
                "verdict": "phishing",
                "combined_score": 0.9,
                "rule_score": 0.9,
                "rule_hits": [],
            },
        )
        analysis_id = resp.json()["id"]

        entries = client.get("/audit/log").json()
        assert len(entries) == 1
        assert entries[0]["action"] == "phishing_analysis.created"
        assert entries[0]["resource_id"] == analysis_id
        assert "phishing" in entries[0]["detail"]

    def test_risk_assessment_creates_audit_entry(self, client):
        resp = client.post(
            "/risk/assessments",
            json={
                "source": "phishing.eml",
                "risk_score": 0.9,
                "risk_level": "critical",
                "factors": [],
            },
        )
        assessment_id = resp.json()["id"]

        entries = client.get("/audit/log").json()
        assert len(entries) == 1
        assert entries[0]["action"] == "risk_assessment.created"
        assert entries[0]["resource_id"] == assessment_id

    def test_entries_ordered_newest_first(self, client):
        client.post(
            "/dlp/scans", json={"source": "a.txt", "findings": [], "ner_ran": False}
        )
        client.post(
            "/dlp/scans", json={"source": "b.txt", "findings": [], "ner_ran": False}
        )
        entries = client.get("/audit/log").json()
        assert len(entries) == 2
        assert entries[0]["detail"] == "source='b.txt', findings=0"
        assert entries[1]["detail"] == "source='a.txt', findings=0"

    def test_filter_by_resource_type(self, client):
        client.post(
            "/dlp/scans", json={"source": "a.txt", "findings": [], "ner_ran": False}
        )
        client.post(
            "/phishing/analyses",
            json={
                "source": "b.eml",
                "verdict": "clean",
                "combined_score": 0.0,
                "rule_score": 0.0,
                "rule_hits": [],
            },
        )
        entries = client.get(
            "/audit/log", params={"resource_type": "phishing_analysis"}
        ).json()
        assert len(entries) == 1
        assert entries[0]["resource_type"] == "phishing_analysis"

    def test_filter_by_action(self, client):
        client.post(
            "/dlp/scans", json={"source": "a.txt", "findings": [], "ner_ran": False}
        )
        entries = client.get(
            "/audit/log", params={"action": "risk_assessment.created"}
        ).json()
        assert entries == []

    def test_respects_limit(self, client):
        for i in range(3):
            client.post(
                "/dlp/scans",
                json={"source": f"file{i}.txt", "findings": [], "ner_ran": False},
            )
        entries = client.get("/audit/log", params={"limit": 2}).json()
        assert len(entries) == 2


class TestAuditFailureIsolation:
    def test_broken_audit_logging_does_not_break_dlp_submission(self, client, monkeypatch):
        def exploding_record_audit_event(*args, **kwargs):
            raise RuntimeError("simulated audit logging failure")

        monkeypatch.setattr(
            "undercover.api.routes.dlp.record_audit_event", exploding_record_audit_event
        )
        resp = client.post(
            "/dlp/scans", json={"source": "email.txt", "findings": [], "ner_ran": False}
        )
        assert resp.status_code == 201

    def test_broken_audit_logging_does_not_break_phishing_submission(
        self, client, monkeypatch
    ):
        def exploding_record_audit_event(*args, **kwargs):
            raise RuntimeError("simulated audit logging failure")

        monkeypatch.setattr(
            "undercover.api.routes.phishing.record_audit_event",
            exploding_record_audit_event,
        )
        resp = client.post(
            "/phishing/analyses",
            json={
                "source": "phishing.eml",
                "verdict": "clean",
                "combined_score": 0.0,
                "rule_score": 0.0,
                "rule_hits": [],
            },
        )
        assert resp.status_code == 201

    def test_broken_audit_logging_does_not_break_risk_submission(self, client, monkeypatch):
        def exploding_record_audit_event(*args, **kwargs):
            raise RuntimeError("simulated audit logging failure")

        monkeypatch.setattr(
            "undercover.api.routes.risk.record_audit_event", exploding_record_audit_event
        )
        resp = client.post(
            "/risk/assessments",
            json={"source": "clean.eml", "risk_score": 0.0, "risk_level": "low", "factors": []},
        )
        assert resp.status_code == 201

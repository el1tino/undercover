import pytest

pytest.importorskip("fastapi")

RAW_PHISHING_EMAIL = (
    "From: PayPal Support <support@paypal-security.net>\n"
    "Subject: Verify your account immediately\n"
    "\n"
    "Dear valued customer, we detected unusual activity. Act now or your "
    "account will be closed. Visit http://192.168.1.5/login now.\n"
)

RAW_CLEAN_EMAIL = (
    "From: Jane Doe <jane@example.com>\n"
    "Subject: Meeting notes\n"
    "\n"
    "Here are the notes from our meeting today.\n"
)


class TestReportEmail:
    def test_reports_phishing_email(self, client):
        resp = client.post(
            "/report/email",
            json={
                "source": "reported.eml",
                "raw_email": RAW_PHISHING_EMAIL,
                "use_ml": False,
                "check_anomaly": False,
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["risk_level"] in {"medium", "high", "critical"}
        assert body["sender_email"] == "support@paypal-security.net"
        assert body["status"] == "open"
        assert len(body["rule_hits"]) > 0

    def test_rule_hits_carry_mitre_techniques(self, client):
        resp = client.post(
            "/report/email",
            json={
                "source": "reported.eml",
                "raw_email": RAW_PHISHING_EMAIL,
                "use_ml": False,
                "check_anomaly": False,
            },
        )
        body = resp.json()
        urgency_hit = next(h for h in body["rule_hits"] if h["name"] == "urgency_language")
        assert urgency_hit["mitre_techniques"][0]["id"] == "T1566"

    def test_clean_email_reports_low_risk(self, client):
        resp = client.post(
            "/report/email",
            json={
                "source": "clean.eml",
                "raw_email": RAW_CLEAN_EMAIL,
                "use_ml": False,
                "check_anomaly": False,
            },
        )
        body = resp.json()
        assert body["risk_level"] == "low"

    def test_persists_both_phishing_analysis_and_risk_assessment(self, client):
        resp = client.post(
            "/report/email",
            json={
                "source": "reported.eml",
                "raw_email": RAW_PHISHING_EMAIL,
                "use_ml": False,
                "check_anomaly": False,
            },
        )
        body = resp.json()

        analysis_resp = client.get(f"/phishing/analyses/{body['phishing_analysis_id']}")
        assert analysis_resp.status_code == 200
        assert analysis_resp.json()["source"] == "reported.eml"

        assessment_resp = client.get(f"/risk/assessments/{body['id']}")
        assert assessment_resp.status_code == 200

    def test_creates_audit_entries_for_both_resources(self, client):
        client.post(
            "/report/email",
            json={
                "source": "reported.eml",
                "raw_email": RAW_PHISHING_EMAIL,
                "use_ml": False,
                "check_anomaly": False,
            },
        )
        entries = client.get("/audit/log").json()
        actions = {e["action"] for e in entries}
        assert "phishing_analysis.created_via_report" in actions
        assert "risk_assessment.created_via_report" in actions

    def test_reported_email_feeds_future_anomaly_detection(self, client):
        pytest.importorskip("sklearn")
        # Report the same aggressive sender many times, plus a few normal
        # senders, then confirm the anomaly report picks up the reported
        # sender's history -- proving /report/email's phishing analysis
        # actually feeds Phase 4 rather than being a dead end.
        for _ in range(20):
            client.post(
                "/report/email",
                json={
                    "source": "reported.eml",
                    "raw_email": RAW_PHISHING_EMAIL,
                    "use_ml": False,
                    "check_anomaly": False,
                },
            )
        for name in ["alice", "bob", "carol"]:
            for _ in range(3):
                client.post(
                    "/phishing/analyses",
                    json={
                        "source": "clean.eml",
                        "sender_email": f"{name}@acme.example",
                        "verdict": "clean",
                        "combined_score": 0.1,
                        "rule_score": 0.1,
                        "rule_hits": [],
                    },
                )

        resp = client.get("/anomaly/senders")
        body = resp.json()
        assert body["skip_reason"] is None
        flagged = {r["sender_email"] for r in body["results"] if r["is_anomaly"]}
        assert "support@paypal-security.net" in flagged

    def test_appears_in_case_list(self, client):
        client.post(
            "/report/email",
            json={
                "source": "reported.eml",
                "raw_email": RAW_PHISHING_EMAIL,
                "use_ml": False,
                "check_anomaly": False,
            },
        )
        resp = client.get("/ui/cases")
        assert "reported.eml" in resp.text

    def test_default_use_ml_true_degrades_gracefully_without_sklearn(self, client):
        # use_ml defaults to True; if scikit-learn isn't installed this
        # should still degrade gracefully rather than 500.
        resp = client.post(
            "/report/email", json={"source": "reported.eml", "raw_email": RAW_CLEAN_EMAIL}
        )
        assert resp.status_code == 201

import pytest

pytest.importorskip("fastapi")


def _finding(**overrides):
    finding = {
        "type": "ssn",
        "label": "US Social Security Number",
        "value": "*******6789",
        "start": 0,
        "end": 11,
        "source": "regex",
        "confidence": 0.85,
    }
    finding.update(overrides)
    return finding


class TestCreateScan:
    def test_creates_scan_with_findings(self, client):
        payload = {
            "source": "email.txt",
            "findings": [_finding()],
            "ner_ran": False,
            "ner_skip_reason": None,
        }
        resp = client.post("/dlp/scans", json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert body["source"] == "email.txt"
        assert body["id"] > 0
        assert len(body["findings"]) == 1
        assert body["findings"][0]["type"] == "ssn"

    def test_creates_scan_with_no_findings(self, client):
        payload = {
            "source": "clean.txt",
            "findings": [],
            "ner_ran": True,
            "ner_skip_reason": None,
        }
        resp = client.post("/dlp/scans", json=payload)
        assert resp.status_code == 201
        assert resp.json()["findings"] == []

    def test_rejects_missing_source(self, client):
        resp = client.post("/dlp/scans", json={"findings": []})
        assert resp.status_code == 422


class TestListScans:
    def test_returns_summaries_newest_first(self, client):
        client.post(
            "/dlp/scans",
            json={"source": "a.txt", "findings": [], "ner_ran": False},
        )
        client.post(
            "/dlp/scans",
            json={
                "source": "b.txt",
                "findings": [_finding(type="email", label="Email", value="x@y.com")],
                "ner_ran": False,
            },
        )
        resp = client.get("/dlp/scans")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 2
        assert body[0]["source"] == "b.txt"  # most recent first
        assert body[0]["finding_count"] == 1
        assert body[1]["finding_count"] == 0

    def test_respects_limit(self, client):
        for i in range(3):
            client.post(
                "/dlp/scans",
                json={"source": f"file{i}.txt", "findings": [], "ner_ran": False},
            )
        resp = client.get("/dlp/scans", params={"limit": 2})
        assert len(resp.json()) == 2


class TestGetScan:
    def test_returns_full_detail(self, client):
        create_resp = client.post(
            "/dlp/scans",
            json={"source": "email.txt", "findings": [_finding()], "ner_ran": False},
        )
        scan_id = create_resp.json()["id"]

        resp = client.get(f"/dlp/scans/{scan_id}")
        assert resp.status_code == 200
        assert resp.json()["findings"][0]["label"] == "US Social Security Number"

    def test_missing_scan_returns_404(self, client):
        resp = client.get("/dlp/scans/999999")
        assert resp.status_code == 404

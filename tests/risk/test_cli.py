"""Unit tests for the undercover-risk CLI entry point."""

import io
import json

from undercover.risk.cli import main

RAW_CLEAN_EMAIL = (
    "From: Jane Doe <jane@example.com>\n"
    "Subject: Meeting notes\n"
    "\n"
    "Here are the notes from our meeting today.\n"
)

RAW_PHISHING_EMAIL = (
    "From: PayPal Support <support@paypal-security.net>\n"
    "Subject: Verify your account immediately\n"
    "\n"
    "Dear valued customer, we detected unusual activity. Act now or your "
    "account will be closed. Visit http://192.168.1.5/login now.\n"
)

# --no-anomaly-check is used throughout to keep these tests hermetic --
# without it, the CLI tries to reach the API (which is fine, it degrades
# gracefully, but we don't want a real/absent server to affect assertions).
COMMON_FLAGS = ["--no-ner", "--no-ml", "--no-anomaly-check"]


def test_clean_email_is_low_risk(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_CLEAN_EMAIL))
    exit_code = main(COMMON_FLAGS)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "LOW" in captured.out


def test_phishing_email_is_flagged(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_PHISHING_EMAIL))
    exit_code = main(COMMON_FLAGS)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "risk level:" in captured.out
    assert "Factors:" in captured.out


def test_json_format_is_valid_json(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_PHISHING_EMAIL))
    main(COMMON_FLAGS + ["--format", "json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["risk_level"] in {"low", "medium", "high", "critical"}
    assert payload["source"] == "<stdin>"


def test_cef_format_starts_with_cef_header(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_PHISHING_EMAIL))
    main(COMMON_FLAGS + ["--format", "cef"])
    captured = capsys.readouterr()
    assert captured.out.startswith("CEF:0|undercover|")


def test_fail_on_risk_threshold_exits_one(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_PHISHING_EMAIL))
    exit_code = main(COMMON_FLAGS + ["--fail-on-risk", "low"])
    assert exit_code == 1


def test_fail_on_risk_not_reached_exits_zero(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_CLEAN_EMAIL))
    exit_code = main(COMMON_FLAGS + ["--fail-on-risk", "critical"])
    assert exit_code == 0


def test_anomaly_check_disabled_notes_reason(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_CLEAN_EMAIL))
    main(COMMON_FLAGS)
    captured = capsys.readouterr()
    assert "disabled via --no-anomaly-check" in captured.out


def test_scans_a_file(tmp_path, capsys):
    sample = tmp_path / "sample.eml"
    sample.write_text(RAW_PHISHING_EMAIL)
    exit_code = main(COMMON_FLAGS + [str(sample)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert f"Risk assessment for {sample}" in captured.out


def test_submit_to_unreachable_api_warns_but_does_not_crash(tmp_path, capsys):
    sample = tmp_path / "sample.eml"
    sample.write_text(RAW_CLEAN_EMAIL)
    exit_code = main(
        COMMON_FLAGS
        + ["--submit", "--api-url", "http://127.0.0.1:59999", str(sample)]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Warning: could not submit to API" in captured.err


def test_anomaly_check_against_unreachable_api_degrades_gracefully(capsys, monkeypatch):
    # Without --no-anomaly-check, but pointed at an unreachable API: should
    # still complete and just note the anomaly check couldn't run.
    monkeypatch.setattr("sys.stdin", io.StringIO(RAW_CLEAN_EMAIL))
    exit_code = main(["--no-ner", "--no-ml", "--api-url", "http://127.0.0.1:59999"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Sender anomaly check: skipped" in captured.out


def test_check_attachments_without_api_keys_degrades_gracefully(tmp_path, capsys, monkeypatch):
    from email.message import EmailMessage as StdlibEmailMessage

    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("MALWAREBAZAAR_API_KEY", raising=False)

    stdlib_msg = StdlibEmailMessage()
    stdlib_msg["From"] = "jane@example.com"
    stdlib_msg["Subject"] = "See attached"
    stdlib_msg.set_content("See attached invoice.")
    stdlib_msg.add_attachment(
        b"fake-content", maintype="application", subtype="octet-stream",
        filename="invoice.exe",
    )
    sample = tmp_path / "sample.eml"
    sample.write_text(stdlib_msg.as_string())

    exit_code = main(COMMON_FLAGS + ["--check-attachments", str(sample)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "invoice.exe: unchecked" in captured.out
    assert "could not be checked" in captured.out

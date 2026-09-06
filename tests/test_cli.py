"""Unit tests for the undercover CLI entry point."""

import json

import pytest

from undercover.cli import main


def test_clean_input_exits_zero(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("Nothing sensitive."))
    exit_code = main(["--no-ner"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "No sensitive data found" in captured.out


def test_finding_with_fail_on_find_exits_one(monkeypatch):
    monkeypatch.setattr(
        "sys.stdin", __import__("io").StringIO("jane.doe@example.com")
    )
    exit_code = main(["--no-ner", "--fail-on-find"])
    assert exit_code == 1


def test_json_output_is_valid_json(capsys, monkeypatch):
    monkeypatch.setattr(
        "sys.stdin", __import__("io").StringIO("jane.doe@example.com")
    )
    main(["--no-ner", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "findings" in payload
    assert payload["findings"][0]["type"] == "email"


def test_scans_a_file(tmp_path, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("Card: 4111111111111111")
    exit_code = main(["--no-ner", str(sample)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Credit Card Number" in captured.out


def test_submit_to_unreachable_api_warns_but_does_not_crash(tmp_path, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("Nothing sensitive here.")
    exit_code = main(
        ["--no-ner", "--submit", "--api-url", "http://127.0.0.1:59999", str(sample)]
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Warning: could not submit to API" in captured.err

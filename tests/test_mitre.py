"""Unit tests for undercover.mitre."""

from undercover.mitre import RULE_HIT_TECHNIQUES, TECHNIQUES, techniques_for_rule_hit
from undercover.phishing.rules import RULES


def test_every_mapped_technique_id_exists_in_registry():
    for technique_ids in RULE_HIT_TECHNIQUES.values():
        for tid in technique_ids:
            assert tid in TECHNIQUES


def test_known_rule_maps_to_expected_technique():
    techniques = techniques_for_rule_hit("urgency_language")
    assert [t.id for t in techniques] == ["T1566"]


def test_link_rules_map_to_spearphishing_link():
    for rule_name in [
        "link_ip_host",
        "link_shortener",
        "link_suspicious_tld",
        "link_anchor_mismatch",
    ]:
        techniques = techniques_for_rule_hit(rule_name)
        assert [t.id for t in techniques] == ["T1566.002"]


def test_impersonation_rules():
    for rule_name in ["spoofed_display_name", "reply_to_mismatch"]:
        techniques = techniques_for_rule_hit(rule_name)
        assert [t.id for t in techniques] == ["T1656"]


def test_generic_greeting_is_untagged():
    assert techniques_for_rule_hit("generic_greeting") == []


def test_unknown_rule_name_returns_empty_list():
    assert techniques_for_rule_hit("not_a_real_rule") == []


def test_technique_has_id_name_and_url():
    technique = TECHNIQUES["T1566"]
    assert technique.id == "T1566"
    assert technique.name
    assert technique.url.startswith("https://attack.mitre.org/")


def test_every_actual_rule_function_name_is_covered_by_the_mapping():
    """Every rule check function in undercover.phishing.rules that can
    produce a RuleHit must have a (possibly empty) entry here -- an
    unmapped name silently falls back to "untagged", which should be a
    deliberate choice (like generic_greeting), not an oversight."""
    from undercover.phishing.email_message import EmailMessage

    msg = EmailMessage(
        sender_display_name="PayPal Support",
        sender_email="support@paypal-security.net",
        reply_to_email="someone@another-domain.example",
        subject="Verify your account immediately",
        body="Dear valued customer, act now or your account will be closed.",
        links=["http://192.168.1.5/login", "http://bit.ly/x", "http://free.top/x"],
        anchors=[("paypal.com", "http://evil.example/login")],
    )
    hit_names = {hit.name for rule in RULES for hit in rule(msg)}
    assert hit_names, "expected at least one rule to fire for this crafted message"
    for name in hit_names:
        assert name in RULE_HIT_TECHNIQUES, f"{name!r} has no entry in RULE_HIT_TECHNIQUES"

"""Unit tests for individual phishing rules and the RuleEngine."""

from undercover.phishing.email_message import EmailMessage
from undercover.phishing.rules import (
    RuleEngine,
    check_generic_greeting,
    check_sender_reply_to_mismatch,
    check_spoofed_display_name,
    check_suspicious_links,
    check_urgency_language,
)


def make_message(**overrides) -> EmailMessage:
    defaults = dict(
        sender_display_name="Jane Doe",
        sender_email="jane@example.com",
        reply_to_email=None,
        subject="Hello",
        body="Just a normal message.",
        body_html=None,
        links=[],
        anchors=[],
    )
    defaults.update(overrides)
    return EmailMessage(**defaults)


class TestUrgencyLanguage:
    def test_detects_urgency_phrase(self):
        msg = make_message(body="Please verify your account immediately.")
        hits = check_urgency_language(msg)
        assert any(h.name == "urgency_language" for h in hits)

    def test_clean_body_has_no_hits(self):
        msg = make_message(body="Here are the notes from our meeting.")
        assert check_urgency_language(msg) == []

    def test_checks_subject_too(self):
        msg = make_message(subject="Your account will be closed", body="See attached.")
        hits = check_urgency_language(msg)
        assert any(h.name == "urgency_language" for h in hits)


class TestGenericGreeting:
    def test_detects_generic_greeting(self):
        msg = make_message(body="Dear Valued Customer, please review the attached.")
        hits = check_generic_greeting(msg)
        assert len(hits) == 1

    def test_personal_greeting_no_hit(self):
        msg = make_message(body="Hi Jane, please review the attached.")
        assert check_generic_greeting(msg) == []


class TestSuspiciousLinks:
    def test_flags_ip_host(self):
        msg = make_message(links=["http://192.168.1.5/login"])
        hits = check_suspicious_links(msg)
        assert any(h.name == "link_ip_host" for h in hits)

    def test_flags_url_shortener(self):
        msg = make_message(links=["http://bit.ly/abc123"])
        hits = check_suspicious_links(msg)
        assert any(h.name == "link_shortener" for h in hits)

    def test_flags_suspicious_tld(self):
        msg = make_message(links=["http://free-prize.top/claim"])
        hits = check_suspicious_links(msg)
        assert any(h.name == "link_suspicious_tld" for h in hits)

    def test_flags_anchor_mismatch(self):
        msg = make_message(anchors=[("paypal.com", "http://evil.example/login")])
        hits = check_suspicious_links(msg)
        assert any(h.name == "link_anchor_mismatch" for h in hits)

    def test_legit_link_no_hits(self):
        msg = make_message(links=["https://example.com/docs"])
        assert check_suspicious_links(msg) == []


class TestSpoofedDisplayName:
    def test_flags_brand_name_with_wrong_domain(self):
        msg = make_message(
            sender_display_name="PayPal Support",
            sender_email="support@paypal-security.net",
        )
        hits = check_spoofed_display_name(msg)
        assert any(h.name == "spoofed_display_name" for h in hits)

    def test_no_hit_when_domain_matches_brand(self):
        msg = make_message(
            sender_display_name="PayPal Support", sender_email="support@paypal.com"
        )
        assert check_spoofed_display_name(msg) == []

    def test_no_hit_when_no_brand_referenced(self):
        msg = make_message(sender_display_name="Jane Doe", sender_email="jane@acme.com")
        assert check_spoofed_display_name(msg) == []


class TestSenderReplyToMismatch:
    def test_flags_mismatched_domains(self):
        msg = make_message(
            sender_email="jane@acme.com", reply_to_email="jane@totally-different.com"
        )
        hits = check_sender_reply_to_mismatch(msg)
        assert len(hits) == 1

    def test_no_hit_when_domains_match(self):
        msg = make_message(
            sender_email="jane@acme.com", reply_to_email="jane@acme.com"
        )
        assert check_sender_reply_to_mismatch(msg) == []

    def test_no_hit_when_no_reply_to(self):
        msg = make_message(sender_email="jane@acme.com", reply_to_email=None)
        assert check_sender_reply_to_mismatch(msg) == []


class TestRuleEngine:
    def test_score_is_sum_of_weights_capped_at_one(self):
        msg = make_message(
            sender_display_name="PayPal Support",
            sender_email="support@paypal-security.net",
            subject="Verify your account immediately",
            body="Dear valued customer, act now or your account will be closed.",
            links=["http://192.168.1.5/login", "http://bit.ly/x"],
            reply_to_email="someone@another-domain.com",
        )
        evaluation = RuleEngine().evaluate(msg)
        assert 0.0 < evaluation.score <= 1.0
        assert len(evaluation.hits) >= 4

    def test_clean_message_scores_zero(self):
        msg = make_message()
        evaluation = RuleEngine().evaluate(msg)
        assert evaluation.score == 0.0
        assert evaluation.hits == []


class TestRuleHitMitreTechniques:
    def test_urgency_language_tagged_as_phishing(self):
        msg = make_message(body="Please verify your account immediately.")
        hits = check_urgency_language(msg)
        techniques = hits[0].mitre_techniques
        assert [t.id for t in techniques] == ["T1566"]

    def test_spoofed_display_name_tagged_as_impersonation(self):
        msg = make_message(
            sender_display_name="PayPal Support",
            sender_email="support@paypal-security.net",
        )
        hits = check_spoofed_display_name(msg)
        techniques = hits[0].mitre_techniques
        assert [t.id for t in techniques] == ["T1656"]

    def test_generic_greeting_has_no_techniques(self):
        msg = make_message(body="Dear Valued Customer, please review the attached.")
        hits = check_generic_greeting(msg)
        assert hits[0].mitre_techniques == []

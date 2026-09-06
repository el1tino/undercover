"""Unit tests for PhishingDetector, the rules+ML combiner."""

from undercover.phishing.detector import PhishingDetector
from undercover.phishing.email_message import EmailMessage


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


class TestPhishingDetectorRulesOnly:
    def test_clean_message_is_clean(self):
        detector = PhishingDetector(use_ml=False)
        result = detector.analyze(make_message())
        assert result.verdict == "clean"
        assert result.ml_score is None
        assert result.ml_skip_reason is None
        assert result.combined_score == result.rule_score

    def test_obvious_phishing_scores_above_clean(self):
        detector = PhishingDetector(use_ml=False)
        phishing_msg = make_message(
            sender_display_name="PayPal Support",
            sender_email="support@paypal-security.net",
            subject="Verify your account immediately",
            body=(
                "Dear valued customer, we detected unusual activity. Act now "
                "or your account will be closed."
            ),
            links=["http://192.168.1.5/login"],
        )
        result = detector.analyze(phishing_msg)
        assert result.verdict in {"suspicious", "phishing"}
        assert result.combined_score > 0

    def test_to_dict_shape(self):
        detector = PhishingDetector(use_ml=False)
        result = detector.analyze(make_message())
        d = result.to_dict()
        assert set(d.keys()) == {
            "verdict",
            "combined_score",
            "rule_score",
            "ml_score",
            "ml_skip_reason",
            "rule_hits",
        }

    def test_rule_hits_include_mitre_techniques(self):
        detector = PhishingDetector(use_ml=False)
        phishing_msg = make_message(
            body="Please verify your account immediately or it will be closed."
        )
        result = detector.analyze(phishing_msg)
        d = result.to_dict()
        urgency_hit = next(h for h in d["rule_hits"] if h["name"] == "urgency_language")
        assert urgency_hit["mitre_techniques"] == [
            {
                "id": "T1566",
                "name": "Phishing",
                "url": "https://attack.mitre.org/techniques/T1566/",
            }
        ]

    def test_untagged_rule_has_empty_techniques_list(self):
        detector = PhishingDetector(use_ml=False)
        msg = make_message(body="Dear Valued Customer, please review the attached.")
        result = detector.analyze(msg)
        d = result.to_dict()
        greeting_hit = next(h for h in d["rule_hits"] if h["name"] == "generic_greeting")
        assert greeting_hit["mitre_techniques"] == []


class TestPhishingDetectorWithMlRequested:
    def test_degrades_gracefully_or_produces_a_score(self):
        # Whether or not scikit-learn is installed in this environment,
        # analyze() should never raise, and should always report one of
        # the two valid states for the ML component.
        detector = PhishingDetector(use_ml=True)
        result = detector.analyze(make_message())
        assert (result.ml_score is not None) or (result.ml_skip_reason is not None)

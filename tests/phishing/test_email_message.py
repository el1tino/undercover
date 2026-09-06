"""Unit tests for EmailMessage.from_raw parsing."""

from email.message import EmailMessage as StdlibEmailMessage

from undercover.phishing.email_message import EmailMessage


def _build_raw_plain(**headers) -> str:
    msg = StdlibEmailMessage()
    msg["From"] = headers.get("From", "Jane Doe <jane@example.com>")
    msg["To"] = "someone@example.com"
    msg["Subject"] = headers.get("Subject", "Hello")
    if "Reply-To" in headers:
        msg["Reply-To"] = headers["Reply-To"]
    msg.set_content(headers.get("body", "Just a normal message."))
    return msg.as_string()


def _build_raw_html(html_body: str, plain_body: str | None = None, **headers) -> str:
    msg = StdlibEmailMessage()
    msg["From"] = headers.get("From", "Jane Doe <jane@example.com>")
    msg["To"] = "someone@example.com"
    msg["Subject"] = headers.get("Subject", "Hello")
    msg.set_content(plain_body or "plain fallback")
    msg.add_alternative(html_body, subtype="html")
    return msg.as_string()


class TestPlainTextParsing:
    def test_parses_display_name_and_email(self):
        raw = _build_raw_plain(From="Jane Doe <jane@example.com>")
        msg = EmailMessage.from_raw(raw)
        assert msg.sender_display_name == "Jane Doe"
        assert msg.sender_email == "jane@example.com"

    def test_parses_subject_and_body(self):
        raw = _build_raw_plain(Subject="Meeting notes", body="See you at 3pm.")
        msg = EmailMessage.from_raw(raw)
        assert msg.subject == "Meeting notes"
        assert "See you at 3pm." in msg.body

    def test_parses_reply_to(self):
        raw = _build_raw_plain(**{"Reply-To": "someone-else@other.com"})
        msg = EmailMessage.from_raw(raw)
        assert msg.reply_to_email == "someone-else@other.com"

    def test_no_reply_to_is_none(self):
        raw = _build_raw_plain()
        msg = EmailMessage.from_raw(raw)
        assert msg.reply_to_email is None

    def test_extracts_links_from_plain_body(self):
        raw = _build_raw_plain(body="Please visit http://example.com/reset now.")
        msg = EmailMessage.from_raw(raw)
        assert "http://example.com/reset" in msg.links


class TestHtmlParsing:
    def test_extracts_anchor_text_and_href(self):
        html = (
            "<html><body>"
            '<a href="http://evil.example/login">paypal.com</a>'
            "</body></html>"
        )
        raw = _build_raw_html(html)
        msg = EmailMessage.from_raw(raw)
        assert ("paypal.com", "http://evil.example/login") in msg.anchors

    def test_falls_back_to_stripped_html_when_no_plain_part(self):
        html_only = StdlibEmailMessage()
        html_only["From"] = "Jane Doe <jane@example.com>"
        html_only["Subject"] = "Hi"
        html_only.set_content(
            "<html><body><p>Hello world</p></body></html>", subtype="html"
        )
        msg = EmailMessage.from_raw(html_only.as_string())
        assert "Hello world" in msg.body
        assert "<p>" not in msg.body

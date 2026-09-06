"""SPF/DKIM/DMARC header analysis.

This does not perform live SPF/DKIM/DMARC verification (that requires
DNS lookups and, for DKIM, cryptographic signature verification against
the exact bytes the sending server signed -- see Known Limitations in
docs/phase5-risk-scoring.md). Instead it parses the
`Authentication-Results` header(s) a message already carries, which is
where a receiving mail server records the SPF/DKIM/DMARC verdicts it
already computed (RFC 8601) -- the same source Gmail, Outlook, and most
mail security tooling read this information from.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field

# Deliberately permissive: scans for `method=result` pairs anywhere in the
# header value rather than implementing RFC 8601's full ABNF grammar. Real
# Authentication-Results headers vary a lot between mail providers, and this
# pattern matches the common ones (Gmail, Outlook/Microsoft 365, generic
# MTAs) without needing an exact grammar match.
_METHOD_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AuthResult:
    mechanism: str  # "spf" | "dkim" | "dmarc"
    result: str  # "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror" | ...


@dataclass
class HeaderAuthReport:
    authentication_results_present: bool
    spf: AuthResult | None = None
    dkim: AuthResult | None = None
    dmarc: AuthResult | None = None
    has_dkim_signature: bool = False
    raw_authentication_results: list[str] = field(default_factory=list)

    def risk_contribution(self) -> tuple[float, str]:
        """A 0-1 risk value plus a human-readable reason, for
        undercover.risk.scoring to fold into the unified risk score."""
        if not self.authentication_results_present:
            return 0.3, "no Authentication-Results header found"

        results = {
            r.mechanism: r.result
            for r in (self.spf, self.dkim, self.dmarc)
            if r is not None
        }
        if results.get("dmarc") == "fail":
            return 1.0, "DMARC authentication failed"
        if results.get("spf") == "fail" or results.get("dkim") == "fail":
            return 0.7, "SPF or DKIM authentication failed"
        if results and all(v == "pass" for v in results.values()):
            return 0.0, "SPF/DKIM/DMARC all passed"
        return 0.4, "SPF/DKIM/DMARC present but inconclusive"


def parse_authentication_results(header_value: str) -> list[AuthResult]:
    """Extract spf=/dkim=/dmarc= result pairs from one Authentication-Results
    header's value."""
    return [
        AuthResult(mechanism=match.group(1).lower(), result=match.group(2).lower())
        for match in _METHOD_RESULT_RE.finditer(header_value)
    ]


def analyze_headers(raw_email: str) -> HeaderAuthReport:
    """Parse a raw RFC 5322 message and summarize its auth-related headers.

    When a message has multiple Authentication-Results headers (added by
    each hop in a multi-hop delivery), the first one is used -- headers
    are prepended by each new hop, so the first is the one added closest
    to final delivery, which is the one a receiving client would trust.
    """
    msg = email.message_from_string(raw_email, policy=email.policy.default)

    ar_headers = [str(h) for h in (msg.get_all("Authentication-Results") or [])]
    has_dkim_signature = msg.get("DKIM-Signature") is not None

    results = parse_authentication_results(ar_headers[0]) if ar_headers else []

    def first(mechanism: str) -> AuthResult | None:
        return next((r for r in results if r.mechanism == mechanism), None)

    return HeaderAuthReport(
        authentication_results_present=bool(ar_headers),
        spf=first("spf"),
        dkim=first("dkim"),
        dmarc=first("dmarc"),
        has_dkim_signature=has_dkim_signature,
        raw_authentication_results=ar_headers,
    )

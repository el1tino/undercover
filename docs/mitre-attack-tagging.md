# MITRE ATT&CK Tagging

The third "later addition": phishing rule hits now carry the ATT&CK
technique(s) they correspond to, so a detection reads as "T1566.002 --
Spearphishing Link" instead of just an internal rule name -- the
vocabulary a SOC/threat-intel audience already uses.

## What gets tagged, and what doesn't

Only `undercover.phishing.rules.RuleHit` (Phase 2's rule engine)
carries MITRE tags:

| Rule                       | Technique                                    |
|-----------------------------|-----------------------------------------------|
| `urgency_language`          | T1566 -- Phishing                             |
| `link_ip_host`               | T1566.002 -- Phishing: Spearphishing Link     |
| `link_shortener`              | T1566.002 -- Phishing: Spearphishing Link     |
| `link_suspicious_tld`          | T1566.002 -- Phishing: Spearphishing Link     |
| `link_anchor_mismatch`           | T1566.002 -- Phishing: Spearphishing Link     |
| `spoofed_display_name`             | T1656 -- Impersonation                        |
| `reply_to_mismatch`                  | T1656 -- Impersonation                        |
| `generic_greeting`                     | *(untagged)*                                  |

**DLP findings (Phase 1), the anomaly signal (Phase 4), and the
header-auth signal (Phase 5) are deliberately left untagged.** ATT&CK
techniques describe an *adversary's* behavior. A DLP finding describes
data present in a message -- "this text contains something that looks
like a credit card number" isn't an attacker technique, it's a fact
about the message's content, true regardless of whether it arrived via
attack or was just someone's own careless email. Anomaly detection and
header-auth results are aggregate/contextual signals rather than one
discrete observed behavior, so forcing a single technique ID onto them
would manufacture a connection that isn't really there. `generic_greeting`
is excluded for the same kind of reason at the rule level: it's too
weak a signal on its own (plenty of legitimate bulk mail starts "Dear
Customer") to confidently claim it demonstrates a specific technique.

Being honest about what *isn't* tagged, and why, matters more here than
tagging everything -- a security tool that overclaims which of its
signals map to real adversary behavior is worse than one that's
selective about it.

## Where it shows up

**`undercover-phish`** (human and `--json` output):

```
  Rule hits:
    - [urgency_language] Urgency phrase found: 'verify your account' (weight 0.15) -- ATT&CK: T1566 (Phishing)
    - [spoofed_display_name] Display name references 'paypal' but sender domain 'paypal-security.net' does not belong to it (weight 0.40) -- ATT&CK: T1656 (Impersonation)
```

**`undercover-risk`** adds a consolidated summary at the bottom of its
human output, deduplicating techniques across every rule hit that fired:

```
  MITRE ATT&CK techniques observed:
    - T1566: Phishing (https://attack.mitre.org/techniques/T1566/)
    - T1656: Impersonation (https://attack.mitre.org/techniques/T1656/)
```

**The API** (`GET /phishing/analyses/{id}`) includes `mitre_techniques`
on each rule hit in the response, computed from the stored rule `name`
at read time -- see Design decisions below for why nothing new is
persisted.

## Design decisions

- **Nothing new is stored in the database.** A rule hit's techniques
  are a deterministic function of its `name` (see
  `undercover.mitre.techniques_for_rule_hit`), so
  `PhishingRuleHit.mitre_techniques` is a `@property` on the
  SQLAlchemy model -- computed at read time from the already-stored
  `name` column, mirroring how `DlpScan.finding_count` and
  `PhishingAnalysis.rule_hit_count` are computed properties rather than
  stored columns. No migration needed, and the mapping can be
  corrected or extended later without touching historical data.
- **`RuleHit.mitre_techniques` is a property, not a constructor
  argument.** Adding technique IDs to each of the ~8 individual rule
  check functions in `rules.py` would mean touching every one of them;
  a property computed from `self.name` via the shared lookup table
  means the mapping lives in exactly one place
  (`undercover.mitre.RULE_HIT_TECHNIQUES`).
- **`undercover.mitre` has no dependencies of its own** (just a
  dataclass and two dicts), so importing it from `phishing/rules.py`,
  `phishing/detector.py`, and `api/models.py` doesn't add any new
  optional-dependency surface -- unlike NER, the ML classifier, or the
  network-calling modules, MITRE tagging is always on, for everyone.

## Testing

```bash
pytest tests/test_mitre.py tests/phishing/test_rules.py tests/phishing/test_detector.py
pip install -e ".[dev,api]"
pytest tests/api/test_phishing_routes.py
```

`tests/test_mitre.py` includes a completeness check
(`test_every_actual_rule_function_name_is_covered_by_the_mapping`) that
runs every real rule function against a crafted message and asserts
every `RuleHit.name` that can actually fire has an entry in
`RULE_HIT_TECHNIQUES` -- so a future new rule added to `rules.py`
without updating the MITRE mapping fails this test rather than quietly
shipping untagged.

## Known limitations

- **Coverage is intentionally partial.** Eight rules, three techniques,
  four of Phase 2's phishing rules untagged or partially tagged is not
  comprehensive MITRE ATT&CK coverage of phishing -- it's what this
  project's actual detections honestly support today. Extending
  Phase 2 with new rules (e.g. detecting a specific credential-harvesting
  page pattern -> T1566.002 more specifically, or a BEC-style wire
  transfer request -> T1534 Internal Spearphishing) would extend this
  mapping too.
- **One rule can map to multiple techniques in principle, but none
  currently do** -- the mapping is `dict[str, list[str]]` to support
  that, but every current mapping is zero or one technique.
- **No sub-technique disambiguation beyond what's listed.** T1566
  ("Phishing") is used for `urgency_language` as the general parent
  technique rather than picking a specific sub-technique, since urgency
  language alone doesn't indicate *how* the phishing was delivered
  (link vs. attachment vs. voice) the way `link_*` rules do.

# Attachment Scanning (VirusTotal + MalwareBazaar)

The first of the roadmap's "later additions": checks email attachments
against known-malware databases instead of ignoring them entirely.
This is opt-in (`--check-attachments`) because, unlike every other
signal `undercover-risk` computes, it makes real outbound network
requests and needs API keys to do anything useful.

## What it does

1. `EmailMessage.from_raw` (Phase 2) now also extracts each attachment
   as an `Attachment(filename, content_type, sha256, size_bytes)` --
   the SHA-256 is computed locally; the file content itself never
   leaves the machine.
2. `undercover.attachments.virustotal.VirusTotalClient` and
   `undercover.attachments.malwarebazaar.MalwareBazaarClient` each look
   up that hash against their respective service (`GET /files/{hash}`
   for VirusTotal's public API v3; `query=get_info` for MalwareBazaar).
   **Neither ever uploads the file** -- both are hash-lookup-only calls.
3. `AttachmentScanner` queries both sources for every attachment and
   combines them: an attachment is `malicious` if *either* source flags
   it. `summarize_attachment_risk()` reduces a batch of per-attachment
   verdicts to one 0-1 value and a human-readable reason, which
   `undercover.risk.scoring.assess_risk()` folds in as a fifth factor
   (`attachments`, weight 0.15 -- the other four weights were rebalanced
   slightly to make room: phishing 0.40, DLP 0.20, header auth 0.15,
   sender anomaly 0.10).

## Why hash lookup, not upload-and-scan

VirusTotal and MalwareBazaar both support uploading a file for
analysis, not just looking up a hash you already computed. This
project deliberately only does hash lookups:

- **Privacy**: uploading an attachment sends its full content to a
  third party. A hash lookup sends only a 64-character SHA-256 digest
  -- enough to check "has anyone seen this exact file before," nothing
  about its content.
- **It's also just correct for this tool's job.** `undercover-risk` is
  meant to be fast triage over an already-received email, not a
  malware sandbox. A hash lookup answers "is this a known-bad file" in
  one request; an upload-and-wait-for-analysis flow can take minutes
  and doesn't fit a CLI that's meant to give an answer immediately.
- The tradeoff: a **novel** malicious attachment nobody has submitted
  to either service yet won't be caught. This is a real limitation
  (see below), not a hidden one.

## Setup

```bash
pip install -e ".[attachments]"    # or [api] -- both just need httpx

export VT_API_KEY="your-virustotal-api-key"              # optional
export MALWAREBAZAAR_API_KEY="your-abuse.ch-auth-key"    # optional
```

Get a VirusTotal key at https://www.virustotal.com/gui/my-apikey (free
tier available) and a MalwareBazaar Auth-Key at
https://bazaar.abuse.ch/account/. Either, both, or neither can be
configured -- `undercover-risk --check-attachments` degrades per-source:
an attachment is reported "unchecked" only if *neither* configured
source could be reached, and the risk factor's detail always says
exactly why (missing key, missing httpx, network failure, or genuinely
checked-and-clean).

## Usage

```bash
undercover-risk --check-attachments suspect_email.eml
```

```
Risk assessment for suspect_email.eml
  risk level: HIGH
  risk score: 0.71
  ...
  Attachments:
    - invoice.exe: MALICIOUS
        [virustotal] 45/71 engines flagged this file as malicious
        [malwarebazaar] listed in MalwareBazaar as 'Emotet'
```

Without `--check-attachments`, `undercover-risk` still extracts and
lists attachment metadata (via `EmailMessage.attachments`) but never
calls out to either service -- consistent with every other signal
being either local-only or opt-in before making a network call.

## Testing

```bash
pip install -e ".[dev,attachments]"
pytest tests/attachments tests/phishing/test_email_message.py::TestAttachmentParsing
```

Client tests never make real network calls -- `httpx.get`/`httpx.post`
are always monkeypatched with a crafted response (malicious hash, clean
hash, not-found, HTTP error, connection error), and are split into
skip-if-httpx-missing / skip-if-httpx-present classes like every other
optional-dependency test in this project. There is no automated test
against the real VirusTotal or MalwareBazaar APIs -- doing so would
require committing a real API key and would make the suite flaky
against services outside this project's control. Manual verification
with a real key is a reasonable thing to do once, not something to
wire into CI.

## Known limitations

- **Hash lookup only catches known malware.** A targeted, novel
  attachment that's never been submitted to either service scores as
  "checked, not flagged" -- indistinguishable from genuinely clean.
  This is the fundamental tradeoff of hash-based detection versus
  sandboxing or static/behavioral analysis, not a bug.
- **No real API key was available to test this against the live
  services during development** (this project's dev environment has
  neither `VT_API_KEY` nor `MALWAREBAZAAR_API_KEY` set). Response
  parsing is verified against each API's documented JSON shape and
  exercised by the mocked tests, but hasn't been exercised against a
  live VirusTotal/MalwareBazaar response. If you configure a real key,
  worth a manual spot-check with a known sample (e.g. the EICAR test
  file's hash) before relying on this in a real workflow.
- **MalwareBazaar's "malicious" is binary** (found = malware, not found
  = no opinion) since it's a malware-sample-only database -- it can't
  express VirusTotal's "12 engines out of 70" nuance.
- **Rate limits aren't handled specially.** A free-tier VirusTotal key
  is limited to a handful of requests per minute; this doesn't retry,
  back off, or batch -- a burst of attachments could hit 429s, which
  surface as a generic "VirusTotal returned HTTP 429" detail.

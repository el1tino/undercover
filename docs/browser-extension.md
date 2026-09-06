# Browser Extension: One-Click Reporting

The final "later addition" from the original roadmap. A Manifest V3
extension (Chrome/Edge) that sends an email straight to the undercover
API for full analysis, without needing the CLI or Python installed.

## What it does

1. Paste an email's raw source into the popup (Gmail: **Show
   original**; Outlook: **View message source**) -- or click
   **"Use current page text"** for a best-effort capture of whatever's
   currently visible in the active tab.
2. Click **Report to undercover**.
3. The popup `fetch()`s `POST {apiUrl}/report/email` (see
   docs/case-management-and-dashboard.md) and shows the verdict --
   risk level, score, and the top contributing factors -- right in the
   popup, with a link straight into the case's dashboard page.

That single endpoint runs the same DLP + phishing + header + anomaly
pipeline `undercover-risk` runs locally, so the extension needs no
local Python, no CLI, and no email-parsing logic of its own beyond
grabbing text out of the page.

## Why paste raw source rather than "just read the open email"

There's no universal way to extract a structured, header-intact email
from an arbitrary webmail provider's DOM -- every provider (Gmail,
Outlook Web, Yahoo, ProtonMail...) renders differently, and reading
`document.body.innerText` only ever gets *visible rendered text*, not
the underlying `From`/`Subject`/`Authentication-Results` headers the
analysis pipeline actually uses for sender identification and header
checks. Pasting the raw message source (every major webmail client has
a "view original"/"show source" feature) gives `EmailMessage.from_raw`
real headers to work with. The "Use current page text" button is
included as a fast, honest-about-its-limits fallback for a quick
gut-check -- the popup UI and this doc both say plainly that it won't
have sender/SPF/DKIM information.

## Setup

1. `pip install -e ".[api]" && undercover-api` (needs to be reachable
   at the URL you configure in step 3 -- `http://127.0.0.1:8000` by
   default).
2. In Chrome/Edge: `chrome://extensions` -> enable **Developer mode**
   -> **Load unpacked** -> select the `browser-extension/` directory.
3. Click the extension's icon, open the gear icon, and set the API URL
   if it isn't running on the default `http://127.0.0.1:8000`.

## Why it can reach `localhost` (and other hosts) without CORS trouble

The FastAPI server has no CORS middleware configured -- a plain
browser tab calling `fetch()` against it cross-origin would be
blocked. Extension pages (the popup, the background service worker)
are different: **Manifest V3's `host_permissions` let an extension
bypass CORS entirely for hosts it has permission for**, regardless of
what the target server's headers say. The manifest declares
`http://localhost/*` and `http://127.0.0.1/*` upfront (the default
`undercover-api` deployment target); if you point the extension at a
different host, `popup.js`'s `ensureHostPermission()` calls
`chrome.permissions.request()` for that specific origin, triggered by
your click on Save/Report -- a real user gesture, as MV3's permission
model requires; it never asks for blanket access to every site up
front.

## Manifest permissions, and why each one

| Permission | Why |
|---|---|
| `activeTab` | Read the active tab's title/URL as a fallback `source` label, and permit the one-time page-text capture. |
| `scripting` | Run the page-text-capture snippet (`document.body.innerText`) in the active tab when "Use current page text" is clicked. |
| `storage` | Remember the configured API URL across popup opens (`chrome.storage.sync`). |
| `host_permissions: localhost/127.0.0.1` | Talk to the default local API without a permission prompt. |
| `optional_host_permissions: http(s)://*/*` | Requested narrowly, only for a specific host the user actually configures -- never granted upfront. |

No `background` permission beyond a minimal service worker that sets
a default API URL on install (`background.js`) -- there's no
persistent monitoring, no reading of mail content without the user
explicitly pasting or clicking capture.

## Testing

There's no pytest coverage here -- this is a separate JS codebase, not
part of the Python package (`tests/` doesn't include it, and
`pyproject.toml` doesn't reference it). It was instead verified with
Playwright driving a real Manifest V3 load in Chromium:

```bash
pip install playwright   # Python bindings; this environment's
                          # Chromium binary is already present
xvfb-run -a python3 verify_extension.py   # needs a display; the repo
                                           # doesn't ship this script --
                                           # see below for what it checked
```

The verification (not committed -- it's a one-off manual check, not a
regression test, since there's no CI wiring for a browser extension in
this project) loaded the unpacked extension with
`--load-extension`/`--disable-extensions-except`, opened the popup at
its `chrome-extension://<id>/popup.html` URL, saved a custom API URL
(exercising the real `chrome.permissions.request()` flow), pasted a
crafted phishing email, clicked Report, and confirmed: the popup
showed the correct risk level and factors from a real running
`undercover-api` instance, the case link was well-formed, and
following it rendered a real case detail page. This confirms the
extension, the API, and the CORS-via-host-permissions mechanism all
work together end-to-end, not just that the JS has no syntax errors.

## Known limitations

- **No automated regression testing.** The Playwright check above was
  run once, by hand, during development -- there's no CI job that
  re-verifies the extension on every change. A real product would want
  that; this is a portfolio-scale addition.
- **Page-text capture is best-effort**, as covered above -- no
  sender/header information, so the risk assessment from that path
  leans entirely on DLP and phishing-body signals.
- **No Firefox/Safari manifest.** This targets Chrome/Edge (Manifest
  V3) only; Firefox's MV3 support has some API differences
  (`browser.*` vs `chrome.*`, different permission semantics) not
  accounted for here.
- **The extension has no icon artwork beyond a generated placeholder**
  (a solid circle in the project's accent color) -- functional, not
  designed.

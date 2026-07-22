# ClientSideEye — BApp Store Submission Draft

## 1. Proposed name

**ClientSideEye** (unchanged — already reasonably brandable; see the "Clear name and
description" note in `PORTSWIGGER_COMPLIANCE.md` for why the summary below is written to make
the specific scope explicit, since the name alone does not fully convey it).

## 2. One-line summary

> Finds password values, hidden/disabled action controls, and other client-side authorization
> anti-patterns left in HTML and JavaScript — plus optional live-DOM capture for single-page apps.

## 3. Full BApp description

ClientSideEye is a passive analysis extension that helps testers quickly locate client-side
security anti-patterns that are easy to miss by eye in large HTML/JS responses:

- **Plaintext password values** left in `<input type="password" value="...">` fields.
- **Hidden or disabled interactive controls** (buttons, links, form elements, or `role="button"`
  elements) that are still wired to real client-side actions (`onclick`, form submission, hrefs,
  `data-action`/`data-url` attributes) — a common sign that authorization is being enforced only
  in the UI, not on the server.
- **Role/permission hints** leaking into client-rendered markup.
- **Inline scripts that look like they contain hard-coded secrets/tokens.**
- **DevTools-blocking/detection logic**, with a ready-to-use bypass snippet for authorized
  testing.
- **JavaScript endpoint/route references, DOM-XSS sink usage, and `postMessage` handlers**,
  surfaced from both regular script tags and JS assets.
- **Exposed source maps** (`.js.map` responses and `//# sourceMappingURL` references), including
  re-analysis of any JavaScript recovered from a source map's `sourcesContent`.

Every finding includes a severity/confidence score, an evidence snippet, a plain-English
recommendation, and (for HTML-sourced findings) a generated **Find Hint** — a ready-to-paste
browser DevTools console snippet that locates, highlights, or safely reveals the exact element,
so the tester can manually confirm whether server-side authorization is actually missing.
ClientSideEye never exploits anything itself; it is a triage/discovery aid for **manual**
verification.

An optional companion browser extension (bundled in the same GitHub repository) can relay
findings from the **live, rendered DOM** of a page the tester is browsing — including SPA/
hash-routed views that never appear as a discrete server response — over a token-authenticated,
loopback-only local bridge into the same ClientSideEye tab.

## 4. Unique value compared with existing BApps

- Focuses specifically on **client-side authorization anti-patterns** (hidden/disabled controls
  still wired to real actions, passwords rendered into the DOM) — a narrower and more actionable
  niche than general "find JS files" or "list endpoints" tooling.
- Generates **actionable, copy-pasteable DevTools console snippets** tailored to each specific
  finding (locate / highlight / reveal / DevTools-bypass), turning a static finding into a fast
  manual-verification workflow.
- Includes an **optional runtime DOM capture bridge** for SPA/hash-route pages that have no
  discrete server-rendered equivalent to analyze from Site Map/Proxy history alone.
- This is **not** a duplicate of DOM Invader (which is an active, canary-based DOM
  XSS/prototype-pollution/clobbering tester driven from the browser toolbar) or of
  Retire.js-style extensions (which fingerprint known-vulnerable *library versions*).
  ClientSideEye does neither of those things.

*(See `PORTSWIGGER_COMPLIANCE.md` for the caveat that a live BApp Store search for overlapping
extensions should be performed by the maintainer immediately before submission.)*

## 5. How it works

1. ClientSideEye statically analyzes HTML/JavaScript/source-map response bodies that Burp has
   already retrieved (Site Map, Proxy history, Repeater, Logger) — it makes **no outbound HTTP
   requests of its own**.
2. Analysis runs entirely on a dedicated background thread; results are merged (deduplicated by
   a stable identity key) into an in-memory table in the "ClientSideEye" Burp tab.
3. An optional local bridge (`127.0.0.1`, default port `17373`) accepts findings posted by the
   companion browser extension, authenticated with a per-session token shown in the Burp tab.

## 6. Installation and setup

1. Download the latest `ClientSideEye-Burp-<version>.jar` (or build with `gradle clean jar`).
2. In Burp: **Extensions → Installed → Add**, select **Java**, choose the jar.
3. Confirm the "ClientSideEye" tab appears and the extension output log shows the bridge
   listening address and token.
4. *(Optional)* Load `browser-extension/clientsideeye-bridge/` as an unpacked Chromium
   extension for live-DOM capture; paste the token from the ClientSideEye tab into its popup.

## 7. Usage instructions

- Browse the target normally, then either:
  - Right-click one or more requests in Proxy/Target/Repeater/Logger → **Send to
    ClientSideEye**, or
  - Click **Analyze Site Map (in-scope)** in the ClientSideEye tab.
- Triage findings by Severity/Confidence; use the Host/Search/Type/Severity filters to narrow
  down a large result set.
- Select a finding and click **View in Browser…** to get Find Hint snippets for manual
  DevTools-based confirmation.
- Export the current (optionally filtered) result set as JSON via **Export JSON…**.

## 8. Supported Burp editions and versions

- **Editions:** Burp Suite Professional and Community Edition (no Professional-only Montoya
  API surface — e.g. no `Scanner`/audit-issue APIs — is used).
- **Montoya API version compiled against:** `2025.12`. The maintainer should confirm and state
  the corresponding minimum Burp Suite desktop release in the final BApp Store listing (not
  independently verified in this review — no running Burp instance was available).
- **Java:** Requires Java 17 (matches the Gradle toolchain declaration); Burp Suite bundles a
  compatible JRE for extensions, so end users do not need to separately install Java.

## 9. Privacy and network behavior disclosures

- **No telemetry, no update checks, no cloud/AI service calls of any kind.**
- **No outbound HTTP requests are made by the extension itself** — all analysis operates on
  data Burp has already fetched.
- The extension **opens one local, loopback-only (`127.0.0.1`) TCP listener** (default port
  `17373`, with automatic fallback to `17374`–`17382` if busy) to receive findings from the
  optional companion browser extension. This listener:
  - Is not reachable from any other host on the network (bound explicitly to `127.0.0.1`).
  - Requires a random, per-session token (displayed only in the Burp UI/output) for the
    finding-submission endpoint.
  - Grants CORS only to browser-extension origins (`chrome-extension://`, `moz-extension://`,
    `safari-web-extension://`), not to arbitrary web pages.
  - Is entirely optional — the core analysis features (Site Map scan, right-click send-to) work
    fully without it and without the companion browser extension ever being installed.
- The companion browser extension stores the bridge token in its own local
  (`chrome.storage.local`) storage only; nothing is sent to any third party.

## 10. Known limitations

- Detection is heuristic and regex/DOM-pattern based; it will produce both false positives
  (e.g. flagging a cosmetically hidden, non-interactive `<div>`) and false negatives on heavily
  obfuscated or unusually structured code. Findings are explicitly framed as **signals for
  manual review**, not confirmed vulnerabilities.
- The optional Browser Bridge is a local convenience feature, not a hardened multi-tenant
  service; any other local process that can read the displayed token can submit spoofed
  findings (see `SECURITY_REVIEW.md`, finding `SEC-04` — an accepted, disclosed risk for this
  threat model).
- Very large Site Map scans currently have no mid-scan cancellation button (only a pre-scan
  confirmation above a size threshold).
- No automated large-project/performance benchmarking has been performed against a real,
  multi-thousand-item Burp project as part of this review (see `TEST_PLAN.md`).

## 11. GitHub repository readiness checklist

- [x] Public GitHub repository containing all extension source code (`src/main`, `src/test`)
      and the companion browser extension source (`browser-extension/`).
- [x] Clear `README.md` covering installation, usage, Finding Types, the Browser Bridge
      protocol, security model, troubleshooting, and non-goals.
- [x] `LICENSE` present (MIT).
- [x] `CHANGELOG.md` present and up to date with this review's fixes.
- [x] `.gitignore` present; build caches/output no longer tracked (fixed in this review).
- [x] No secrets, credentials, or personal developer paths committed (fixed in this review —
      removed `push.sh`).
- [ ] **Not yet done by this review** (requires the maintainer's own GitHub account/CI access):
  add a CI workflow (e.g. GitHub Actions) that runs `gradle clean build` on every push/PR, so
  the "builds and tests pass" state verified manually in this review is continuously enforced.
- [ ] **Not yet done:** final live BApp Store overlap search (see §4 caveat).
- [ ] **Not yet done:** the manual Burp-instance tests listed in `TEST_PLAN.md` §2 (load/unload,
      large Site Map, Browser Bridge end-to-end).

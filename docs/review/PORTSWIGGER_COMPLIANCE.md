# ClientSideEye — PortSwigger BApp Store Compliance

**Documentation reviewed:** PortSwigger's official *BApp Store acceptance criteria* page
(`https://portswigger.net/burp/documentation/desktop/extensions/creating/bapp-store-acceptance-criteria`),
successfully retrieved and quoted/paraphrased below. Page metadata shown by PortSwigger:
**"Last updated: June 18, 2026"**.

**Review date of this document:** 2026-07-22.

**Note on documentation coverage:** The specific "Submitting extensions to the BApp Store"
process page could not be located at the URL slugs attempted during this review (all returned
404); the acceptance-criteria page itself was retrieved successfully and is the primary source
for the criteria below. The general submission mechanism (a public GitHub repository containing
source code, a clear name/description, and documentation covering setup/usage) is stated
directly in this review's own instructions and is consistent with PortSwigger's well-established,
publicly documented BApp Store submission process; this review does not claim to have
independently re-verified the exact current wording of that specific page.

## Compliance matrix

| Requirement (PortSwigger's wording) | Applicable | Status | Evidence | Remediation | Verification method |
|---|---|---|---|---|---|
| **Unique function** — "Make sure that your extension doesn't duplicate the function of an existing extension." | Yes | **Likely compliant, needs manual confirmation** | See "Unique function" analysis below. | None required from a code perspective; recommend a final live BApp Store search immediately before submission (catalog changes over time). | Manual: search the live BApp Store for "client-side", "DOM", "hidden", "disabled" at submission time. |
| **Clear, descriptive name** | Yes | **Compliant, minor wording tightening recommended** | Name "ClientSideEye" plausibly communicates a client-side focus but not the specific "hidden/disabled control + password-in-DOM" niche. `README.md` description is otherwise clear and detailed. | See `SUBMISSION_DRAFT.md` for a tightened one-line summary. | Manual review of the drafted BApp Store listing text before submission. |
| **Operates securely** — "Treat the content of HTTP messages as untrusted... Data entered by a user into the GUI can generally be trusted, but if there is auto-fill from untrusted sources, don't assume the user will check the contents." | Yes | **Fixed** | `SEC-01` (Swing HTML injection via untrusted content auto-filled into the UI from the Browser Bridge) and `SEC-02` (unbounded local listener reads) were found and fixed — see `SECURITY_REVIEW.md`. | Both fixed in this review. | `BrowserBridgeServerNetworkTest` (new); manual verification described in `TEST_PLAN.md`. |
| **Includes all dependencies** — "one-click installation... includes all dependencies." | Yes | **Compliant** | The built jar bundles `org.jsoup:jsoup:1.18.3` (verified present via `unzip -l`); Burp-provided `montoya-api` is correctly excluded (verified absent). No other runtime dependency exists. | None required. | `unzip -l build/libs/ClientSideEye-Burp-0.1.1.jar \| grep -i jsoup` (present) and `\| grep -i montoya` (absent) — both run and confirmed during this review. |
| **Uses threads to maintain responsiveness** — "Don't perform slow operations ... in the Swing EDT... surround the full thread operation with a try/catch and write stack traces to the extension error stream." | Yes | **Compliant, one reliability gap fixed** | All analysis work runs on a dedicated single-thread `ExecutorService` (`bg`), never on the EDT. UI mutations are marshaled back via `SwingUtilities.invokeLater`/`invokeAndWait`. Background work is wrapped in try/catch that logs to `api.logging().logToError(...)` (the extension error stream) — confirmed present in `analyzeSiteMapInScope`, `analyzeSelection`, `exportJson`, and `BrowserBridgeServer.handleClient`. The per-item try/catch gap (one bad item aborting a whole batch) was found and fixed in this review. | Fixed (see `CODE_REVIEW.md` #8). | Code inspection + `BrowserBridgeServerNetworkTest`; manual large-Site-Map test in `TEST_PLAN.md`. |
| **Unloads cleanly** — "register an unload handler... background threads are terminated in `ExtensionUnloadingHandler.extensionUnloaded()`." | Yes | **Compliant** | `ClientSideEyeExtension.initialize` calls `api.extension().registerUnloadingHandler(...)`, which stops `BrowserBridgeServer` (closes the listening socket, shuts down both its executors) and calls `bg.shutdownNow()`. | None required. | Manual repeated load/unload test in `TEST_PLAN.md` (not run in this review — requires a live Burp instance). |
| **Uses Burp networking** — "prefer `Http.issueHttpRequest()`... avoid communication to the target from within `ScanCheck.passiveAudit()`." | Yes | **Compliant** | ClientSideEye issues **zero** outbound HTTP requests; it only reads response bodies Burp already fetched (`HttpRequestResponse.response().bodyToString()`). No `java.net.URL`/`HttpURLConnection`/`HttpClient`/OkHttp/Apache HttpClient usage exists in `src/main`. `BrowserBridgeServer`'s `ServerSocket` is an **inbound** listener, not an outbound request mechanism, and there is no supported Montoya API for hosting an inbound HTTP listener — a raw socket is the only option for this specific, disclosed feature. There is no `ScanCheck` in this extension at all. | None required for outbound compliance. Recommend the BApp Store listing/description explicitly call out the local listener so reviewers aren't surprised by a `ServerSocket` in the code — done in `SUBMISSION_DRAFT.md`. | `grep` sweep for `java.net.URL\|HttpURLConnection\|HttpClient\|OkHttp\|apache.*http` across `src/main` — run, zero matches outside `BrowserBridgeServer`'s inbound listener code. |
| **Supports offline working** — "extensions that contact an online service to receive vulnerability definitions or other data should include a copy of recent definitions." | Yes (extension contacts no online service) | **Compliant, trivially** | ClientSideEye performs 100% local, static analysis with no vulnerability-definition downloads, no cloud API calls, and no update checks. The Browser Bridge is a **local-only** (127.0.0.1) feature, not an "online service." | None required. | Code inspection (no network client code exists) — confirmed. |
| **Copes with large projects** — "avoid keeping long-term references to objects passed to functions like `HttpHandler.handleHttpRequest()`... take care with `SiteMap.requestResponses()`." | Yes | **Compliant, with one recommendation** | `Finding` objects store only extracted strings (URL, host, a short evidence snippet, ≤ a few hundred characters) — no `HttpRequestResponse` object is ever retained beyond the scope of a single analysis call. `findingsByKey` is capped at `MAX_FINDINGS = 5000` with FIFO eviction. `api.siteMap().requestResponses()` is called once per manual scan (not on every event), and the result is iterated and discarded, not retained. | No code change required. Recommend adding a "Cancel scan" affordance for very large Site Maps (see `CODE_REVIEW.md`) — deferred, not a compliance blocker. | Manual large-Site-Map test in `TEST_PLAN.md` (not run in this review — requires a live Burp project with a large Site Map). |
| **Provides a parent for GUI elements** — "any GUI elements... are children of the main Burp Frame... use `SwingUtils.suiteFrame()`." | Yes | **Compliant** | Every `JDialog`/`JOptionPane` call found in `ClientSideEyeTab.java` passes `api.userInterface().swingUtils().suiteFrame()` as the parent (`showViewInBrowserDialog`, `toggleFalsePositiveForSelection`, `showViewInBrowserDialog`'s missing-selection dialog, `confirmLargeSiteMapScan`). No orphaned top-level windows were found. | None required. | `grep -n "JOptionPane\|new JDialog" src/main/.../ClientSideEyeTab.java` — every call site inspected and confirmed to pass `suiteFrame()`. |
| **Uses the Montoya API artifact** — "reference the `montoya-api` artifact using a build tool like Gradle or Maven." | Yes | **Compliant** | `build.gradle` declares `compileOnly "net.portswigger.burp.extensions:montoya-api:2025.12"` via Maven Central; confirmed absent from the built jar (no copied/bundled API classes). No legacy Extender API usage exists anywhere in the codebase. | None required. | `unzip -l build/libs/ClientSideEye-Burp-0.1.1.jar \| grep -i "burp/api/montoya"` — run, zero matches. |
| **Uses Burp AI as the default AI provider** (only applicable if the extension has AI functionality) | **Not applicable** | N/A | ClientSideEye has no AI functionality of any kind — no LLM calls, no `burp.api.montoya.ai` usage, no third-party AI provider integration. | N/A | Code inspection — confirmed, zero AI-related imports or code. |

## Detailed notes

### Unique function

ClientSideEye's stated differentiators, as implemented in code (not just marketing copy):

- **Passive detection of client-side authorization anti-patterns** — hidden/disabled
  interactive controls that are still present (and often still wired to real handlers) in
  server-rendered HTML, and plaintext password values left in the DOM. This is a narrower,
  more specific niche than general "DOM XSS" or "JS analysis" tooling.
- **A weighted confidence/severity heuristic** (`HtmlAnalyzer.scoreControlSignals`) rather than
  a simple keyword match, specifically tuned to distinguish "actionable" hidden controls
  (onclick/role=button/form actions) from purely cosmetic hidden `<div>`s.
- **"Find Hint" generation** (`FindHintBuilder`) that produces ready-to-paste DevTools
  console snippets (locate/highlight/reveal) tailored to the specific matched element — this is
  a workflow aid not found, to this reviewer's knowledge, in general-purpose JS/DOM analysis
  extensions.
- **An optional companion Browser Bridge** for capturing SPA/hash-route runtime DOM state that
  never appears as a discrete server response — addressing a real gap in purely
  response-body-based analysis (relevant for single-page apps).

This differs from **DOM Invader** (a Chromium DevTools-integrated tool focused on active,
canary-based DOM XSS/prototype-pollution/clobbering testing driven from the browser) and from
**Retire.js**-style extensions (which fingerprint known-vulnerable JS library *versions*) —
ClientSideEye does neither of those things; it does not fingerprint library versions and does
not perform active canary-based testing. It also does not duplicate Burp's own native passive
scanner checks for the same reason: Burp Scanner does not have a purpose-built check for
"hidden/disabled control still wired to a real action" or "password value literally present in
an HTML response," which are the actual core detections here.

**Caveat and recommendation:** this reviewer did not have live access to search the current
BApp Store catalog at the time of this review (no network access to `portswigger.net`'s BApp
listing search was exercised for this specific check — only the documentation pages above were
fetched). **Before submission, the maintainer should personally search the live BApp Store**
for terms like "client-side," "DOM," "hidden control," "disabled button," and "password in DOM"
to confirm no newer overlapping extension has been published since this review. This is called
out explicitly as an **unverified item**, not a pass.

### Clear name and description

"ClientSideEye" is a reasonable, brandable name but does not by itself communicate the specific
"hidden/disabled controls + password-in-DOM + client-side JS/source-map recon" scope — a user
skimming the BApp Store list could easily confuse it with a generic "client-side security
scanner" (of which there are likely several, given the "unique function" caveat above). The
existing `README.md` description is otherwise clear, detailed, and not overstated. See
`SUBMISSION_DRAFT.md` for a recommended tightened one-line summary.

**Unsupported marketing claims check:** `README.md`'s "Non-goals" section explicitly disclaims
exploitation/authorization-bypass claims ("ClientSideEye does not exploit vulnerabilities or
bypass authorization. It highlights client-side anti-patterns for manual validation.") — this
is good, accurate, non-overstated framing and was **not** changed.

### Secure operation

See `SECURITY_REVIEW.md` in full. Summary: two concrete findings (`SEC-01` HTML injection via
attacker-influenced UI content, `SEC-02` unbounded local-listener reads) were found and fixed.
Both map directly to this criterion's explicit language about untrusted HTTP content and
auto-filled GUI data from untrusted sources.

### Dependencies

Confirmed via direct inspection of the built jar (`unzip -l`): `org.jsoup` classes present,
Montoya API classes absent, no duplicate/conflicting classes observed, Mockito (test-only)
absent from the runtime jar. `jsoup` is MIT-licensed (compatible with this project's MIT
license); no attribution/NOTICE file is strictly required for MIT but adding a short
third-party-notices note is a nice-to-have, not a blocker.

### Threading and responsiveness

Compliant as described in the matrix; the one gap found (single-item failures aborting whole
batches, which is a robustness issue rather than a threading-model issue) was fixed. No evidence
of Swing work happening off the EDT, or blocking I/O happening on the EDT, was found anywhere in
`ClientSideEyeTab.java`.

### Clean unloading

Code-level review is compliant (unload handler registered, executors shut down, listening
socket closed). **This review could not perform a live, in-Burp repeated load/unload test**
(no running Burp Suite instance was available in this environment) — this is recorded as a
required manual test in `TEST_PLAN.md`, not claimed as verified.

### Burp networking / offline operation

Both compliant by construction — see matrix. The local Browser Bridge listener is a deliberate,
disclosed exception to "no extra network behavior," is inbound-only, loopback-only, and does
not affect offline operability of the extension's core (Site Map / right-click analysis
workflows require zero network access beyond what Burp itself already needed to fetch the
page).

### Large-project behavior

Compliant by construction (bounded finding store, no long-term `HttpRequestResponse` retention).
**Not empirically load-tested against an actual multi-thousand-item Site Map in this review**
(no live Burp project was available) — see `TEST_PLAN.md` for the manual test to run before
submission.

### GUI ownership and quality

Compliant — every dialog inspected parents to `suiteFrame()`. Additionally hardened in this
review (`SEC-01` fix) so that untrusted finding text cannot alter table/combo-box rendering
behavior via Swing's HTML interpretation.

### Montoya API artifact

Compliant — correct scope, correct exclusion from the runtime jar, no legacy API usage, no
copied API classes.

### AI functionality

Not applicable — no AI functionality exists in this extension.

## Remaining submission blockers

None identified as **hard blockers** at the code level after the fixes in this review. The
following are **required manual verifications** before submission (not yet performed, and
explicitly not claimed as passed):

1. Load the built jar in a real Burp Suite instance (Professional or Community — no
   Pro-only Montoya API surface is used) and confirm it initializes without error.
2. Perform at least 3 repeated load/unload cycles and confirm no error output, no orphaned
   threads (e.g., via a thread dump), and no continued Browser Bridge listener after unload
   (`curl http://127.0.0.1:<port>/api/health` should fail to connect after unload).
3. Run **Analyze Site Map (in-scope)** against a project with a genuinely large Site Map
   (thousands of items) and confirm the UI remains responsive and the warning/confirmation
   dialog appears at the documented threshold.
4. Search the live BApp Store for overlapping extensions immediately before submission (see
   "Unique function" above).
5. Manually verify the `SEC-01` fix by crafting a test page whose element `aria-label`/text
   begins with the literal characters `<html` and confirming it renders as plain text (not
   interpreted markup) in the findings table and the Find-Hint dropdown after this fix.

## Documentation review date and sources

- PortSwigger *BApp Store acceptance criteria* — retrieved 2026-07-22, page shows
  "Last updated: June 18, 2026."
- PortSwigger *Burp extensions* overview page — retrieved 2026-07-22, page shows
  "Last updated: June 18, 2026," confirming the Montoya API is the current recommended/only
  actively-documented extension API path (the "Extender API (Legacy)" is listed separately in
  the navigation as legacy).
- The "Submitting extensions to the BApp Store" process page specifically could not be located
  at the URL slugs attempted; this is disclosed above as an unverified documentation gap rather
  than glossed over.

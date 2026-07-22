# ClientSideEye — Test Plan

## 1. Automated tests (implemented, run, and passing in this review)

Run with: `gradle clean test` (or `gradle clean build`). Result at time of writing: **31/31
tests passing**, 0 failures, 0 skipped, on a clean checkout with Gradle 9.4.0 / Java 17.

| Class | Purpose | Notable cases |
|---|---|---|
| `HtmlAnalyzerTest` | Password-in-DOM, hidden/disabled control, role hints, secretish scripts, DevTools-blocking detection, a11y-only elements, malformed HTML via jsoup, dedupe key stability | New in this review: `recognizesBareTagFragmentsWithoutRequiringSpecificWrapperTags`, `doesNotTreatPlainTextComparisonsAsHtml` (regression tests for the `looksLikeHtmlForAnalysis` fix) |
| `JavaScriptAnalyzerTest` | Endpoint/route reference detection, DOM-XSS sink detection, `postMessage` detection | New in this review: `detectsEndpointAndSinkReferencesWithoutDeclarationKeywordsOrJsExtension`, `analyzeJavaScriptContentBypassesHeuristicGateForKnownJavaScript` (regression tests for the JS-gating fix) |
| `SourceMapAnalyzerTest` | Source-map reference detection, embedded `sourcesContent` re-analysis | Pre-existing `detectsExposedSourceMapAndEmbeddedJavaScriptSignals` now passes (was failing before this review's fixes) |
| `FindHintBuilderTest` | Selector ranking, quote/attribute extraction, text-fallback locator, reveal-snippet generation | Unchanged; already Burp-independent and adequate |
| `BrowserBridgeServerTest` | Pure-function token/size validation (`validateFindingRequest`) | Unchanged |
| `BrowserBridgeServerNetworkTest` **(new in this review)** | End-to-end socket-level regression tests against a real, running `BrowserBridgeServer` instance (using Mockito to stand up a `MontoyaApi` double) | `rejectsRequestLineExceedingMaxLineLength` (asserts `431`), `rejectsExcessiveHeaderCount` (asserts `431`), `healthEndpointStillWorksForWellFormedRequests` (control case, asserts `200`) |

### Regression coverage added for every defect fixed in this review

- Detection false negatives (`HtmlAnalyzer`/`JavaScriptAnalyzer` gating) — covered by the new
  test cases above, plus the 4 pre-existing tests that were failing before the fix and now pass.
- Per-item failure isolation in batch analysis (`ClientSideEyeExtension.analyzeSelection`,
  `ClientSideEyeTab.analyzeSiteMapInScope`) — **not** covered by an automated test in this pass,
  because both methods are private/package-internal to Swing-integrated classes that would
  require substantial additional test scaffolding (a fake `HttpRequestResponse`/`MontoyaApi`
  chain) to exercise directly; recorded here as a manual test instead (see §2 below) rather than
  silently skipped.
- Browser Bridge DoS hardening — covered by `BrowserBridgeServerNetworkTest` (new).
- Swing HTML-injection fix (`SEC-01`) — **not** unit-testable in a meaningful way (it depends on
  `BasicHTML`'s behavior during Swing paint, which requires a realized, painted component in a
  non-headless environment); covered by a manual test instead (see §4 below).

## 2. Manual Burp tests (required before submission — not performed in this review; no live Burp instance was available in this environment)

1. **Load/initialize:** Install the built jar (`ClientSideEye-Burp-0.1.1.jar`) via
   Extensions → Installed → Add (Java) in a real Burp Suite Professional or Community
   instance. Confirm the "ClientSideEye" tab appears and the extension output shows:
   - `[ClientSideEye] Loaded. Use right-click 'Send to ClientSideEye'...`
   - `[ClientSideEye] Browser bridge listening on http://127.0.0.1:<port> ...`
   - `[ClientSideEye] Browser bridge token: <token>`
2. **Passive analysis smoke test:** Browse a small test app containing a password `<input
   type="password" value="secret">` and a hidden `<button aria-disabled="true"
   onclick="doDelete()">`. Right-click the request in Proxy HTTP history → "Send to
   ClientSideEye" and confirm both a `PASSWORD_VALUE_IN_DOM` and a `HIDDEN_OR_DISABLED_CONTROL`
   finding appear in the tab.
3. **Site Map scan:** Click "Analyze Site Map (in-scope)" against the same small test app and
   confirm the same findings appear via that path too, and that the completion log line reports
   `Failed items: 0`.
4. **Per-item failure isolation (regression for the fix in this review):** Manually create/edit
   a Proxy history entry (e.g. via Repeater → send a request whose response body a test proxy
   or match/replace rule corrupts into something that will throw during analysis — e.g. an
   extremely deeply nested HTML fragment, or a response with a `Content-Length` mismatch that
   Burp still stores) alongside normal pages, then multi-select and "Send to ClientSideEye."
   Confirm the log line shows a non-zero `Failed items` count **and** that findings for the
   other, well-formed selected items still appear (this is the behavior the fix in this review
   restores).
5. **Repeated load/unload (required by "unloads cleanly"):**
   - Unload the extension. Confirm no further "[ClientSideEye]" log lines appear.
   - Confirm `curl -sv http://127.0.0.1:<port>/api/health` now fails to connect (connection
     refused) — proves the bridge socket was actually closed.
   - Re-load the extension (Extensions → Installed → re-add or re-enable) and repeat steps 1–4.
     Do this at least 3 times in a row. Confirm no accumulating duplicate menu items, no
     duplicate "ClientSideEye" tabs, and no growing thread count (check via a thread dump or
     the OS process's thread count) across cycles.
6. **Large Site Map:** Browse/import a large test target (or a synthetic large Site Map with
   several thousand entries) and click "Analyze Site Map (in-scope)". Confirm the
   warn-threshold confirmation dialog appears above `SITE_MAP_SCAN_WARN_THRESHOLD` (1000)
   in-scope items, that cancelling the dialog aborts the scan cleanly, and that proceeding
   completes without freezing the Burp UI (the EDT should remain responsive — try
   clicking/resizing other Burp tabs while the scan runs).
7. **Browser Bridge end-to-end:** Load the companion extension from
   `browser-extension/clientsideeye-bridge/` as an unpacked Chromium extension, copy the token
   from the ClientSideEye tab into the popup, click "Scan Current Tab + Send to ClientSideEye"
   against a page with a hidden/disabled control, and confirm the finding appears in the Burp
   tab with `source=browser-extension` in the log line.

## 3. Performance tests

- **Startup/initialize cost:** Not separately profiled; `initialize()` performs only executor
  creation, UI construction, and a socket bind — all fast, bounded operations with no
  measurable startup cost expected. No action needed.
- **Project load/unload cost:** ClientSideEye has no project-file persistence, so opening/
  closing a Burp project has zero interaction with this extension's state. No action needed.
- **Hot-path regex cost on large minified bundles:** Not benchmarked with real large bundles in
  this review (no representative large minified JS sample was available in this environment).
  **Recommended manual test before submission:** feed a multi-hundred-KB minified JS bundle
  (e.g. a real webpack `vendor.js` chunk) through the right-click "Send to ClientSideEye" path
  and time it; if it takes more than ~1–2 seconds on typical hardware, profile
  `JavaScriptAnalyzer`'s regex matchers specifically.

## 4. Security regression tests

| Defect | Automated test | Manual verification |
|---|---|---|
| `SEC-01` Swing HTML injection | None (see rationale above) | Craft a test page with an element whose `aria-label` (or text content) is exactly `<html><img src=http://127.0.0.1:9/x>` (an address guaranteed to fail-fast rather than actually beacon out), send it through the Browser Bridge (or directly via `curl` to `/api/finding` using the token) as the `evidence`/`title` field, and confirm: (a) the findings table shows the literal text `<html><img src=...>` rather than a broken/blank image glyph or altered row height, and (b) the Find-Hint combo box (View in Browser…) shows the same literal text rather than interpreting it. |
| `SEC-02` unbounded bridge reads | `BrowserBridgeServerNetworkTest.rejectsRequestLineExceedingMaxLineLength`, `rejectsExcessiveHeaderCount` (both run, passing) | Optional: run with `-Xmx64m` and repeat the same oversized-line test to additionally confirm no `OutOfMemoryError` under a constrained heap. |
| Detection false negatives (bare-fragment HTML, terse JS) | `HtmlAnalyzerTest`/`JavaScriptAnalyzerTest`/`SourceMapAnalyzerTest` new+previously-failing cases (all run, passing) | N/A |
| Batch analysis abort-on-first-error | None (see rationale above) | Manual test #4 in §2 |

## 5. Large-project / load tests

See manual test #6 above. No automated load test was implemented (would require synthesizing a
large `SiteMap`/`HttpRequestResponse` fixture set, which is out of scope for a minimal,
reviewable change set — flagged as a good candidate for a future contribution).

## 6. Offline tests

- **Automated:** `gradle clean build --offline` was **not** run in this review (the Gradle
  dependency cache in this environment already had the required artifacts from earlier builds
  in this session, so an `--offline` run would not meaningfully prove first-time offline
  capability). This is disclosed as **not run**, not claimed as passed.
- **Manual (recommended before submission):** On a machine with network access fully disabled
  (airplane mode / firewall block), load the extension in Burp and repeat manual tests #2 and
  #3 above (passive analysis and Site Map scan). These should work identically offline, since
  ClientSideEye makes no outbound network calls. The Browser Bridge (loopback-only) should also
  continue to work offline, since `127.0.0.1` traffic does not require internet connectivity.

## 7. Load/unload cycle tests

See manual test #5 above (required, not automatable without a running Burp instance).

## 8. Compatibility tests

- **Java version:** Verified: builds and tests pass with the project's declared toolchain,
  Java 17 (Temurin 17.0.18), using Gradle 9.4.0.
- **Burp edition/version:** **Not independently verified against a running Burp Suite
  instance in this review** (no Burp installation was available in this environment). The
  Montoya API version declared (`2025.12`) should be cross-checked against the minimum Burp
  Suite version that ships that API version before publishing supported-version numbers in the
  BApp Store listing — this is a manual step for the maintainer, who has access to their actual
  Burp installation's version history.
- **OS compatibility:** No OS-specific code exists (pure Java/Swing + a plain TCP socket); no
  OS-specific testing was deemed necessary beyond what was already exercised (macOS, in this
  review environment).

## 9. Commands actually run during this review (for traceability)

```
gradle -v
gradle clean build --console=plain
gradle test --console=plain
gradle test --tests "com.clientsideeye.burp.core.DebugScratchTest" --console=plain -i   # scratch debug, removed afterward
unzip -l build/libs/ClientSideEye-Burp-0.1.1.jar | grep -i montoya   # confirm absent
unzip -l build/libs/ClientSideEye-Burp-0.1.1.jar | grep -i jsoup     # confirm present
unzip -l build/libs/ClientSideEye-Burp-0.1.1.jar | grep -i mockito   # confirm absent
git --no-pager diff --stat
git --no-optional-locks status --porcelain
```

All of the above were executed in this environment and their output is reflected accurately in
`CODE_REVIEW.md`, `SECURITY_REVIEW.md`, and `PORTSWIGGER_COMPLIANCE.md`. No static-analysis
tools (SpotBugs, PMD, Checkstyle, Semgrep, CodeQL, OWASP Dependency-Check, OSV Scanner) were
available/configured in this environment and none were run; this is disclosed explicitly rather
than assumed clean. See `REVIEW_SUMMARY.md` for a recommended minimal toolchain to add.

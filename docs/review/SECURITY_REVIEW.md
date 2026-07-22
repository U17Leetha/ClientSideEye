# ClientSideEye — Security Review

## Threat model

ClientSideEye's job is to analyze **attacker-controlled** content (HTML, JavaScript, source
maps, and — via the optional Browser Bridge — live DOM/storage state of pages the user
browses) and render the results inside Burp Suite's trusted UI process. The primary security
question for a tool like this is not "does it find vulnerabilities correctly" but **"can the
content it is analyzing turn around and attack the analyst's Burp instance, filesystem, or
network?"** All HTTP response bodies, URLs, and browser-page DOM content are treated as hostile
input for the purposes of this review.

Secondary concerns: the extension introduces a new local network listener
(`BrowserBridgeServer`), which is itself attack surface even though it is loopback-only.

## Attack surface

1. HTTP response bodies already retrieved by Burp (Site Map, Proxy history, right-click
   send-to) — parsed by `HtmlAnalyzer` (jsoup + regex) and `JavaScriptAnalyzer`/
   `SourceMapAnalyzer` (regex only).
2. `http://127.0.0.1:<port>/api/health` and `/api/finding` — a hand-rolled HTTP/1.1 server
   listening on loopback, reachable by any local process and by the companion browser
   extension.
3. Content scraped from the live DOM by the companion browser extension and relayed through
   (2) into `Finding` objects, which are subsequently rendered in Swing UI, copied to the
   clipboard, and optionally exported to a JSON file chosen by the user.

## Findings

### SEC-01 — Swing HTML-injection via attacker-controlled finding text (Fixed)

- **Category:** UI / HTML injection · **Severity:** High · **Confidence:** High
- **PortSwigger criterion:** Secure operation — "HTML injection in Swing components", "Unsafe
  rendering through ... HTML-enabled labels, tables".
- **Affected files (before fix):** `src/main/java/com/clientsideeye/burp/ui/ClientSideEyeTab.java`
  (`SeverityRowRenderer`, `showViewInBrowserDialog`'s `hintCombo`).
- **Evidence:** `FindingsTableModel.getValueAt` returns `f.title()`/`f.url()`/`f.host()`
  directly into a `JTable` whose default renderer for `Object.class` was a bare
  `DefaultTableCellRenderer` (a `JLabel` subclass). `showViewInBrowserDialog` populates a
  `JComboBox<String>` with `FindHintBuilder.build(evidence).hints`, where `evidence` is the raw
  `outerHtml()` of a matched DOM element (for Site-Map/HTML-sourced findings) **or** a
  verbatim, attacker-influenced string relayed by the Browser Bridge from
  `browser-extension/clientsideeye-bridge/popup.js`, which scrapes `outer.outerHTML`,
  element text, and attribute values straight out of the live page DOM and POSTs them as the
  `evidence`/`title`/`url` form fields to `/api/finding`.
  Swing's `javax.swing.plaf.basic.BasicHTML` treats any string whose *trimmed* value begins
  with the six characters `<html` (case-insensitively) as HTML markup and renders it with a
  real (if limited) HTML/CSS engine — including resolving `<img src="...">` — unless the
  component's `"html.disable"` client property is set to `Boolean.TRUE`. Neither the table's
  cell renderer nor the combo box's renderer set this property.
- **Impact:** A crafted page element (e.g. `<button aria-label="&lt;html&gt;&lt;img
  src=http://attacker.example/beacon.gif&gt;" ...>`) whose scraped text/attribute begins with
  `<html`, once relayed into a `Finding` and displayed in the findings table or the Find-Hint
  dropdown, would be rendered as HTML by Swing rather than shown as literal text — at minimum
  causing an unintended outbound request from the analyst's machine when the label is painted,
  and more generally allowing the attacker limited control over what is displayed to the
  analyst (a spoofing/confusion vector) purely by having the analyst *view* a finding, no click
  required.
- **Realistic scenario:** Analyst runs the documented workflow ("Scan Current Tab + Send to
  ClientSideEye" from the companion browser extension) against a page they don't fully trust
  (e.g. a multi-tenant SaaS app under test where other tenants can influence rendered content,
  or a reflected-content page). The scraped DOM content flows, unsanitized for Swing-HTML
  purposes, into the findings table the analyst is actively triaging.
- **Fix implemented:** `SeverityRowRenderer` and a new shared `plainTextListCellRenderer()`
  (used for the Find-Hint combo box) now call
  `putClientProperty("html.disable", Boolean.TRUE)` before any text is applied, forcing plain-text
  rendering regardless of content. The Montoya `RawEditor` used for the detail pane and the
  snippet dialog was already safe (it is not an HTML-capable Swing text component).
- **Status:** Fixed. No regression test was added for this specific rendering behavior because
  `BasicHTML`'s interpretation happens inside `LabelUI` painting code, which is impractical to
  assert against in a headless unit test; verification is a manual test (see `TEST_PLAN.md`,
  "Security regression tests").

### SEC-02 — Unbounded line/header reads in the Browser Bridge HTTP parser (Fixed)

- **Category:** Denial of service / resource exhaustion · **Severity:** Medium · **Confidence:** High
- **PortSwigger criterion:** Secure operation — "Maliciously large HTTP messages", "Race
  conditions"/resource exhaustion more broadly.
- **Affected file (before fix):** `src/main/java/com/clientsideeye/burp/integration/BrowserBridgeServer.java`,
  `handleClient` (request line and header loop used `BufferedReader.readLine()`, which has no
  length limit and will buffer an arbitrarily long line fully into memory before returning, and
  the header loop had no cap on the number of headers).
- **Evidence:** `BufferedReader.readLine()` javadoc: reads until a line terminator "or end of
  the input stream", with no size bound. A connecting client could send a single-line request
  or header of unbounded length, or thousands of headers, before ever sending a newline/blank
  line, forcing unbounded buffer growth per connection. `clientExec` is an unbounded
  `Executors.newCachedThreadPool()`, so many such connections could be opened concurrently.
- **Impact:** A local process (malware, another misbehaving local application probing the open
  port, or a bug in the companion browser extension) could exhaust heap memory on the machine
  running Burp. Exposure is limited to local (loopback) callers only, which caps severity at
  Medium rather than High/Critical.
- **Fix implemented:** Added `readBoundedLine(BufferedReader, int)`, which reads
  character-by-character and throws `IOException` once 8 KB is exceeded without a line
  terminator, used for both the request line and each header line; a header-count cap (100)
  was also added. Both cases return `431 Request Header Fields Too Large` and close the
  connection instead of continuing to buffer.
- **Status:** Fixed, with an end-to-end regression test (`BrowserBridgeServerNetworkTest`) that
  opens a real socket to the running server and asserts a `431` response for both an oversized
  request line and an excessive header count, plus a control test asserting normal requests
  still succeed.

### SEC-03 — Detection-quality false negatives (Fixed; tracked as reliability, not just security)

See `CODE_REVIEW.md` items #2–#5. Silently dropping real findings (hidden actionable controls,
`fetch`/`eval` calls in short JS, bare-fragment HTML) is a security-relevant defect for a
security tool: it produces false confidence that a page/script has been analyzed when in fact
key findings were discarded before the heuristic gate. Fixed and covered by regression tests
(`HtmlAnalyzerTest`, `JavaScriptAnalyzerTest`, `SourceMapAnalyzerTest`).

### SEC-04 — Local HTTP listener trust model (Accepted risk, disclosed)

- **Category:** Design / attack surface · **Severity:** Low · **Confidence:** High
- **Details:** Any local process that obtains the bridge token (displayed in the Burp UI/output,
  which is itself only visible to someone with access to the analyst's Burp session) can POST
  spoofed findings into the analyst's ClientSideEye tab. The token is compared with
  `String.equals`, which is not constant-time — a timing side-channel theoretically exists, but
  exploiting it requires an attacker who is *already* a co-resident local process capable of
  making enough precisely-timed local loopback requests to leak a 24-byte random token faster
  than simply reading it from Burp's own extension output/log file, which is a strictly easier
  path for a local attacker. Constant-time comparison was not added because it would not
  meaningfully change the actual risk for this threat model.
- **Also assessed:** CORS is enforced only via `Access-Control-Allow-Origin` (i.e., it protects
  against a malicious *web page* reading the bridge's response, not against a malicious web page
  or DNS-rebound host *sending* a request) — but the token requirement, not CORS, is what
  actually prevents an arbitrary web page (or a DNS-rebinding attack pointing a hostname at
  127.0.0.1) from injecting spoofed findings, since `application/x-www-form-urlencoded` POSTs
  are CORS-safelisted (no preflight) but still require the correct `X-ClientSideEye-Token`
  header, which a same-origin-policy-constrained page cannot read or forge. This design is
  sound as implemented.
- **Status:** Accepted risk — appropriately scoped for a disclosed, opt-in, loopback-only
  developer feature. Recommend the README continue to clearly disclose this (it already does,
  under "Security Model").

### SEC-05 — Repository hygiene: committed build artifacts and developer-specific script (Fixed)

- **Category:** Supply chain / release hygiene · **Severity:** Low (Informational for
  submission, but a real repo-quality issue) · **Confidence:** High.
- **Details:** `.gradle/` caches, compiled `.class` files, the built `.jar`, `.DS_Store` files,
  and a stray duplicate `ClientSideEye-Burp/` directory were committed to git with no
  `.gitignore`. `push.sh` hardcoded a personal filesystem path and a personal GitHub
  remote/handle. None of these are secrets, but they are unnecessary, bloat the repository, and
  (for `push.sh`) disclose developer-identifying information unrelated to the extension.
- **Status:** Fixed — see `CODE_REVIEW.md` items #10–#12.

## Adversarial input review (analysis paths)

- **Regex denial of service:** All regexes in `HtmlAnalyzer`/`JavaScriptAnalyzer`/
  `SourceMapAnalyzer` were reviewed for catastrophic backtracking. Most use bounded quantifiers
  (e.g. `{2,200}`) or character classes without nested unbounded groups, which keeps worst-case
  behavior close to linear. `SourceMapAnalyzer.SOURCES_CONTENT_PATTERN` uses a lazy
  `(.*?)` under `DOTALL` — lazy quantifiers do not exhibit the same catastrophic backtracking as
  nested greedy alternation, and no pathological input was found. No changes made here; flagged
  as **low risk, no action needed** rather than a confirmed issue.
- **Parser bombs / unbounded decompression:** Not applicable — no archive extraction, no XML
  parsing (jsoup's HTML parser is used, not an XML parser, and is not configured to resolve
  external entities; no XXE surface exists). No gzip/deflate handling is performed by this
  extension (Burp decompresses responses before handing bodies to extensions).
- **Excessive recursion:** jsoup's tree parser is iterative for the depths realistically found
  in web pages; no custom recursive descent parsing exists in this codebase.
- **Path traversal / arbitrary file writes:** The only file-write path is **Export JSON…**,
  which uses `JFileChooser` (user explicitly picks the destination) — no filename is derived
  from attacker-controlled data. No path-traversal surface exists.
- **Unsafe deserialization / reflection / dynamic class loading:** None found. No
  `ObjectInputStream`, no reflection-based instantiation of untrusted class names, no
  classloading of remote code.
- **Command/process execution:** None found. No `ProcessBuilder`/`Runtime.exec` anywhere in
  `src/main`.
- **CSV/formula injection:** The only export format is JSON (`JsonExporter`), which escapes
  control characters, quotes, and backslashes correctly (verified by inspection: `esc()` handles
  `\`, `"`, `\n`, `\r`, `\t`, and all other `< 0x20` control characters via `\uXXXX`). No CSV
  export exists, so CSV/formula injection is not applicable.
- **Null-byte / Unicode edge cases:** `Finding`'s constructors coerce `null` to `""`
  (`safe(String)`), and all evidence/summary strings are truncated (`shrink(...)`, typically to
  200–420 characters) before being stored, which limits blast radius from adversarially large
  strings. No explicit Unicode-normalization handling exists, but nothing in the codebase makes
  a security decision based on string equality of attacker-controlled Unicode text in a way
  that a normalization mismatch could bypass (the token comparison in `BrowserBridgeServer` is
  server-generated ASCII, not user-supplied).
- **Malformed/adversarial JavaScript and malicious source maps:** Handled as plain text by
  regex, not executed or `eval`'d anywhere in the extension itself — the extension never runs
  attacker-supplied JavaScript. The only place generated JavaScript "runs" is the
  find-hint/highlight/reveal/bypass **snippets** that `FindHintBuilder` builds for the analyst
  to manually paste into their own browser DevTools console — this is an explicit,
  analyst-initiated action (copy button → paste into console), not automatic execution, and
  matches the project's stated "Non-goals" (no automatic exploitation). String interpolation
  into those snippets is escaped correctly for both single- and double-quoted JS string
  contexts (`jsSingleQuoteEscape`/`jsDoubleQuoteEscape` escape backslash before quote, the
  correct order), preventing an attacker-controlled attribute/text value from breaking out of
  the string literal and injecting arbitrary JS into the snippet the analyst is about to run.
  Unescaped raw line-terminator characters (`\n`, U+2028/U+2029) inside interpolated values can
  still produce a `SyntaxError` when pasted (a usability bug, already acknowledged in
  `README.md`'s troubleshooting section) but cannot achieve script injection, since an
  unterminated string literal simply fails to parse.

## Dependency findings

| Dependency | Scope | Assessment |
|---|---|---|
| `net.portswigger.burp.extensions:montoya-api:2025.12` | `compileOnly` (main), `testImplementation` (test only, added in this review) | Correct scope — Burp provides this at runtime; verified **not** present in the built jar (see `PORTSWIGGER_COMPLIANCE.md`). |
| `org.jsoup:jsoup:1.18.3` | `implementation` | Actively maintained, MIT-licensed, no known unpatched CVEs affecting this extension's usage (HTML parsing only, no `Jsoup.connect(...)` network fetches are used anywhere in this codebase). Correctly shaded into the jar since Burp does not provide it. |
| `org.junit.jupiter:junit-jupiter:5.10.2` + `org.junit.platform:junit-platform-launcher` | test only | Standard, not bundled into the runtime jar (verified). |
| `org.mockito:mockito-core:5.14.2` | `testImplementation` (added in this review) | Standard, widely-used test double library; test-only; not bundled into the runtime jar (verified). Justified by the need to unit-test `BrowserBridgeServer` (a Montoya-integrated class) without launching Burp. |

No dependency-confusion risk was identified (all group IDs are well-established, no
similarly-named typo-squat risk in the declared coordinates). No lock file/verification
metadata (`gradle.lockfile`, dependency verification XML) exists; for a project with only four
runtime/test dependencies this is a reasonable, low-risk omission rather than a blocker, but
adding Gradle dependency verification would be a good low-cost hardening step for a future pass.

## Privacy and data-handling review

- ClientSideEye's core analysis never leaves the local machine: all HTML/JS/source-map
  analysis is done on data Burp already retrieved, in-process, with no outbound network calls.
- The Browser Bridge is loopback-only (`127.0.0.1`), and the companion browser extension's
  `host_permissions` are scoped to exactly the 10 candidate loopback ports — it cannot reach
  any other host.
- The bridge token is displayed in the Burp UI/log output and stored by the companion browser
  extension via `chrome.storage.local` (extension-local storage, not synced, not sent
  anywhere else). No credentials, cookies, or full HTTP histories are ever transmitted to any
  third party — there is no third party in this data flow at all.
- No telemetry, update checks, or any other unsolicited network communication exists anywhere
  in this extension. This satisfies the "no telemetry without explicit documentation" bar
  trivially, since there is none.

## Residual risks (Accepted / Needs Decision)

- **SEC-04** (local trust model of the bridge token) — Accepted risk, appropriately scoped and
  disclosed.
- **Detection false positives** from broadened heuristics (SEC-03 fix) on large minified
  bundles — Accepted risk; this trades a small increase in noise for eliminating a much worse
  false-negative problem, consistent with the tool's purpose as a *triage aid*, not an automated
  verdict. Recommend future tuning informed by real-world usage (see `CODE_REVIEW.md` deferred
  recommendations).
- **No cancellation for long Site Map scans** — Needs Decision; not a security issue but a
  responsiveness concern flagged for the maintainer (see `CODE_REVIEW.md`).

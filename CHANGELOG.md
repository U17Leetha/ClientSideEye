# Change Log

This file tracks changes, improvements, and feature requests for ClientSideEye-Burp.

## 0.2.0 - 2026-07-22

### Browser Bridge: external script and source map fetching
- External `<script src="...">` tags have empty `textContent` in the DOM, so the browser
  scanner previously never read their content at all - only inline `<script>` bodies were
  analyzed. The scanner now fetches a bounded number of external script bodies itself (up to 5
  per scan, 1.5s timeout each, ~400KB cap) so sinks/secrets/endpoints/postMessage/devtools
  patterns are found in them too.
- If a fetched (or inline) script references a source map, the scanner now also fetches the map
  itself (up to 3 per scan, same bounds), parses it, and recursively analyzes any original
  source embedded in `sourcesContent` - closing the gap where source-map-embedded original code
  (often far more revealing than the shipped minified bundle) was only ever analyzed via the
  Java-side Site Map/right-click path, never via the Browser Bridge.
- These fetches run in the page's own context (same-origin, page's own cookies/permissions,
  same as the page's own JS) and fail silently on any error so a single unreachable/oversized
  resource can't abort the rest of a scan.

### Browser Bridge popup UI
- Fixed the three popup buttons ("Save Bridge Token", "Scan Current Tab + Send to
  ClientSideEye", "Watch DOM For 15s + Send") having no spacing between them at all - the
  `button` CSS rule had no `margin`, so they visually ran together as one block. Added
  vertical spacing between all three, and visually separated "Save Bridge Token" (a one-time
  setup action, now styled as a neutral/secondary gray button) from the two scan actions (kept
  as primary blue buttons, grouped together below a divider) so the three are easy to tell
  apart at a glance.

### Browser Bridge parity
- The companion browser extension's runtime scanner (`popup.js`) previously implemented only 6
  of the tool's 12 finding types (`HIDDEN_OR_DISABLED_CONTROL`, `STORAGE_TOKEN`,
  `JAVASCRIPT_ENDPOINT_REFERENCE`, `DOM_XSS_SINK`, `POSTMESSAGE_HANDLER`,
  `RUNTIME_NETWORK_REFERENCE`) - the Java-side `HtmlAnalyzer`/`JavaScriptAnalyzer` implemented
  all 12. If you only ever used the Browser Bridge (Quick/Deep Scan) rather than "Analyze Site
  Map" or right-click "Send to ClientSideEye", several categories of finding - most notably
  plaintext passwords visible in the rendered DOM - would never be reported at all. Brought the
  browser scanner to full parity by adding:
  - `PASSWORD_VALUE_IN_DOM` - reads the live `input.value` (which also catches values set by
    JavaScript after page load, not just ones present in the initial HTML - a strict improvement
    over the Java-side static-attribute check).
  - `ROLE_PERMISSION_HINT`, `INLINE_SCRIPT_SECRETISH`, `DEVTOOLS_BLOCKING`,
    `SOURCE_MAP_DISCLOSURE`, `PROTOTYPE_POLLUTION_HINT`.
  - Framework-specific DOM-XSS sinks (`dangerouslySetInnerHTML`, `[innerHTML]` bindings,
    `bypassSecurityTrustHtml`/`Script`/`ResourceUrl`, `v-html`) and hard-coded
    `WebSocket`/`EventSource` endpoint detection, matching the Java-side additions above.

### Detection fixes (apply to both the Java analyzer and the browser scanner)
- Fixed `ROLE_PERMISSION_HINT` never matching identifiers like `window.__ROLE = 'admin'`.
  The keyword pattern required a leading word boundary before "role", but regex `\b` treats
  underscore as a word character, so there is no boundary between `__` and `ROLE`. The leading
  boundary was dropped (the trailing boundary is kept, so this still can't match arbitrary
  substrings like "parole").
- Fixed `INLINE_SCRIPT_SECRETISH` never matching camelCase identifiers like
  `window.inlineApiKey = "sk_..."`, for the same underlying reason (no word boundary between
  "inline" and "Api"). Same fix applied.

### Bug fixes
- Fixed the "View in Browser..." dialog opening at nearly full monitor width. The Find Hint
  dropdown previously stored each hint as one string containing the label *and* the entire
  multi-line JS snippet concatenated together, which inflated the combo box's computed
  preferred width. Hints are now structured (label, value) pairs, and only the short label is
  shown in the dropdown.
- Fixed "Copy selected Find Hint" copying a corrupted snippet (missing its opening characters,
  with leftover label text prepended) for several hint types, which caused a
  `SyntaxError: Unexpected token ')'` when pasted into the browser console. The previous
  implementation split the display string on the first `": "` it found to separate the label
  from the value, but several labels (e.g. `"Locate (high confidence: data-testid)"`) contain
  their own `": "`, so the split happened in the wrong place. The copy action now uses the
  hint's structured value directly with no string-splitting involved.
- Renamed the "Copy X" buttons in "View in Browser..." to just their target name (e.g. "URL",
  "Find Hint", "Reveal Snippet") with a "Copy to clipboard" tooltip, removing the repetitive
  "Copy" prefix from every button in that row.
- Fixed "Highlight Snippet" appearing to do nothing when the matched element is inside a
  hidden *ancestor* container (e.g. `<div hidden aria-hidden="true">...<button>...</button></div>`,
  the exact "hidden admin panel" pattern this tool targets). Highlight was only applying an
  outline to the matched element itself; if an ancestor isn't rendered, the outline is applied
  but invisible. Highlight now also temporarily un-hides ancestor containers (without touching
  the target element's own disabled/hidden state - that remains Reveal Snippet's job) and
  restores them when the outline is cleared after 4 seconds.
- Fixed "Reveal Snippet" not unmasking `<input type="password">` values. Reveal previously
  only cleared `hidden`/`disabled`/CSS-hiding state on the target and its ancestors, which does
  nothing for a password field masked purely by its `type` attribute. Reveal now also switches
  matched `<input type="password">` elements to `type="text"` so the plaintext value becomes
  visible for client-side-trust testing.
- Made the three console-snippet action rows (Highlight / Reveal / DevTools Bypass) in
  "View in Browser..." visually distinct: added a separator between the locate/copy-URL rows
  and the snippet-action rows, added extra vertical spacing between the three action buttons,
  shortened their row labels ("Highlight:" / "Reveal:" / "DevTools bypass:"), and gave each
  button a specific tooltip describing what it actually does instead of a generic "Copy to
  clipboard" tooltip on all three.
- Generalized "Reveal Snippet" and "Highlight Snippet" so they aren't tailored to any one
  tested application's CSS framework:
  - Reveal's disabled/hidden class cleanup previously removed only a small curated list of
    exact class names (`pf-m-disabled`, `is-disabled`, `btn-disabled`, `disabled`, `hidden`,
    `d-none`), which happened to work against the tool's own test lab but would silently do
    nothing for other naming conventions (Ant Design's `ant-btn-disabled`, Material UI's
    `Mui-disabled`, Bulma's `is-hidden`, etc.). It now strips any class whose name matches a
    disabled/hidden pattern, generalizing across frameworks instead of one app.
  - Both snippets now apply their style overrides (`display`, `visibility`, `opacity`,
    `pointer-events`) with `!important` priority via `setProperty(...)`, and detect hiding via
    `getComputedStyle(...)` rather than only the element's own inline style. Many real CSS
    frameworks hide/disable elements using `!important` utility classes (e.g. Bootstrap's
    `.d-none`/`.invisible`), and a plain non-important inline style assignment silently loses
    that cascade fight, so the previous overrides could "run successfully" while having no
    visible effect on a large share of real-world sites.

### New detection rules
- `JavaScriptAnalyzer` now recognizes framework-specific HTML sinks: React `dangerouslySetInnerHTML`,
  Angular `[innerHTML]` bindings and `bypassSecurityTrustHtml`/`bypassSecurityTrustScript`/
  `bypassSecurityTrustResourceUrl`, and Vue `v-html`.
- Added a new `PROTOTYPE_POLLUTION_HINT` finding type: detects direct `__proto__` access and
  unguarded recursive merge/extend/assign patterns (`_.merge`, `deepmerge`, `$.extend(true, ...)`,
  `Object.assign(..., JSON.parse(...))`) commonly associated with client-side prototype pollution.
- Added detection of hard-coded `WebSocket`/`EventSource` endpoints in JavaScript, reported as
  `RUNTIME_NETWORK_REFERENCE` (previously only produced by the Browser Bridge).

### Performance
- Site Map scans and multi-item right-click "Send to ClientSideEye" analysis no longer schedule
  one full findings-table rebuild per matched page/item. Findings are now batched (flushed every
  100 for Site Map scans, once per selection for right-click) before updating the table, fixing
  an O(n^2) EDT-refresh storm on large scans.

### UX / accessibility
- Host filter and Search fields now have properly associated labels (`setLabelFor`) for screen
  readers.
- Added header tooltips explaining what "Severity", "Confidence", "FP", and "Type" columns
  actually represent, to avoid over-interpreting the heuristic Confidence score as a probability.
- Host filter, Site Map scan limit, and "Export visible rows only" are now persisted across
  extension reloads/Burp restarts via Montoya's `Preferences` store (best-effort; failures are
  logged and never block the UI).

### Engineering
- Extracted the findings table model (`FindingsTableModel`) from a private inner class into a
  standalone, dependency-injected top-level class, enabling direct unit testing without
  constructing the Swing tab. Added a corresponding test suite.
- Added a committed Gradle wrapper (`gradlew`/`gradlew.bat`) for reproducible builds, and a
  GitHub Actions workflow (`.github/workflows/build.yml`) that builds and tests on every push/PR.
- Added `SECURITY.md` with a vulnerability-disclosure process.

## 0.1.1 - 2026-07-22

### Security fixes
- Findings-table and Find-Hint UI controls could render attacker-controlled content
  (finding title/url/evidence sourced from page HTML or the Browser Bridge) as live HTML if it
  began with an `<html` marker, because Swing's default JLabel-based cell/list renderers
  interpret such strings as markup (including remote `<img>` tags). HTML interpretation is now
  force-disabled on these renderers via the `html.disable` client property.
- The Browser Bridge's hand-rolled HTTP parser had no bound on individual header/request-line
  length or header count, allowing a local process to exhaust memory with a single oversized
  line. Line length is now capped (8 KB) and header count is capped (100), both returning
  `431 Request Header Fields Too Large`.

### Bug fixes
- Fixed a detection-quality regression where `HtmlAnalyzer` silently skipped any HTML fragment
  that did not contain one of a fixed list of wrapper tags (`<html>`, `<body>`, `<form>`,
  `<input>`, `<button>`, `<select>`, `<textarea>`), causing bare fragments (e.g. a lone `<div>`
  or `<script>` body) to be dropped without any finding at all.
- Fixed a detection-quality regression where `JavaScriptAnalyzer` silently skipped short/terse
  JavaScript (e.g. extracted source-map `sourcesContent`, or a one-line handler) that lacked
  declaration keywords like `function`/`const`/`=>`, even when it contained clearly dangerous
  calls such as `fetch(...)` or `eval(...)`.
- Fixed hidden/disabled `<div>`/`<span role="button">` controls with direct interactivity
  signals (`onclick`, `role="button"`, `tabindex`) being silently dropped instead of reported,
  even informationally.

### Build/infrastructure
- Added a `.gitignore` and removed committed Gradle build caches, compiled `.class` files,
  `.DS_Store` files, and a stray duplicate project directory that had been checked into git.
- Declared `junit-platform-launcher` explicitly so `gradle test` works on current Gradle/JUnit
  versions.
- Added Mockito as a test-only dependency to enable Burp-independent unit/integration testing of
  Montoya API-integrated classes.

## Unreleased

### Changes
- Improved password value detection to be order-agnostic.
- Expanded hidden/disabled control scanning to additional interactive tags.
- Hardened Find Hints/Reveal selectors for Chrome and Firefox DevTools.
- Added DevTools blocking detection with a console bypass snippet for authorized testing.

### Improvements
- Added unit tests for analyzer findings and DevTools hint generation.

### Feature requests
- None yet.

---

## 0.1.0 - 2026-01-31

### Changes
- Initial release.

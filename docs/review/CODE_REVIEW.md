# ClientSideEye — Code Review

Scope: all files under `src/main/java` and `src/test/java`, build configuration, and the
companion browser extension, as they existed at the start of this review (commit `99c003b`)
and after the fixes described below.

## Summary of changes implemented in this review

| # | File(s) | Change | Reason |
|---|---|---|---|
| 1 | `build.gradle` | Added `testRuntimeOnly "org.junit.platform:junit-platform-launcher"` | `gradle test` failed outright on a clean checkout with Gradle 9.4.0 (`Failed to load JUnit Platform`). This is a hard build blocker. |
| 2 | `src/main/.../core/HtmlAnalyzer.java` | Replaced the fixed keyword allow-list (`<html`,`<body`,`<form`,`<input`,`<button`,`<select`,`<textarea`) in `looksLikeHtmlForAnalysis` with a general "looks like a tag" regex | The old gate silently dropped **all findings** for any HTML fragment that didn't happen to contain one of those 7 substrings — e.g. a bare `<div>` or `<script>` body. Reproduced by 4 pre-existing, previously-failing unit tests. |
| 3 | `src/main/.../core/HtmlAnalyzer.java` | Hidden/disabled `<div>`/`<span>` elements are no longer unconditionally dropped when the weighted "actionable" score is below 60; a new `hasDirectInteractivitySignal` check (onclick/role=button/tabindex) lets them through for at least an informational finding | The exact scenario this tool exists to catch — a hidden `<div role="button" onclick="doDelete()">` — was being silently discarded. Reproduced by a pre-existing, previously-failing unit test. |
| 4 | `src/main/.../core/JavaScriptAnalyzer.java` | Broadened `looksLikeJavaScriptForAnalysis` to recognize call-based patterns (`fetch(`, `eval(`, `axios.`, `.then(`, `addEventListener(`, etc.), and split `analyzeJavaScript` into a gated entry point plus a new ungated `analyzeJavaScriptContent` | Short/terse JS (e.g. a one-line handler, or content extracted from a source map's `sourcesContent`) that lacks `function`/`const`/`=>`/`window.` tokens was silently skipped even when it contained `fetch()`/`eval()` calls. Reproduced by a pre-existing, previously-failing unit test (`SourceMapAnalyzerTest`). |
| 5 | `src/main/.../core/SourceMapAnalyzer.java` | `addEmbeddedSourceFindings` now calls `analyzeJavaScriptContent` instead of the gated `analyzeJavaScript` | Content extracted from a source map's `sourcesContent` array is *known* to be JavaScript; gating it again was the direct cause of finding #4. |
| 6 | `src/main/.../ui/ClientSideEyeTab.java` | `SeverityRowRenderer` (JTable cell renderer) and a new `plainTextListCellRenderer()` (used for the Find-Hint `JComboBox`) now set the `html.disable` Swing client property | Security fix — see `SECURITY_REVIEW.md` finding `SEC-01`. |
| 7 | `src/main/.../integration/BrowserBridgeServer.java` | Replaced unbounded `BufferedReader.readLine()` calls with a new bounded `readBoundedLine` (8 KB/line cap) and added a 100-header cap, both returning `431` | Security/reliability fix — see `SECURITY_REVIEW.md` finding `SEC-02`. |
| 8 | `src/main/.../ClientSideEyeExtension.java`, `src/main/.../ui/ClientSideEyeTab.java` | Wrapped **per-item** analysis in its own try/catch inside the right-click batch handler and the Site Map scan loop, instead of one try/catch around the entire loop | Reliability fix — a single malformed/adversarial response previously aborted analysis of every *remaining* item in a batch or Site Map scan. Now the failure is isolated, logged, and counted (`Failed items: N`), and the rest of the batch still completes. |
| 9 | `build.gradle`, new test files | Added Mockito (test-only) and three new test classes/cases | Enables Burp-independent regression testing of `BrowserBridgeServer`'s network-facing hardening without a running Burp instance. |
| 10 | `.gitignore`, deleted `.gradle/`, `build/`, `.DS_Store`, `ClientSideEye-Burp/` | Removed committed build caches/output and a stray duplicate project directory from the repository | Repository hygiene — see below. |
| 11 | `push.sh` deleted | Removed a personal, hardcoded-path release helper script (`$HOME/Tools/...`, a personal `git@github-personal:` remote alias, and a GitHub handle) | Not relevant to building/using the extension, and discloses developer-specific information that has no place in a public BApp Store submission repo. |
| 12 | `build.sh` | No longer hardcodes the jar filename (`ClientSideEye-Burp-0.1.0.jar`) when copying the build output to the repo root | The hardcoded name would silently go stale on every version bump (it already had, prior to this review). |
| 13 | `CHANGELOG.md`, `build.gradle` (version) | Documented the above and bumped version to `0.1.1` | Standard release hygiene for a fix release. |

All of the above were validated with `gradle clean build` (compiles, packages, all 31 tests
pass) — see `TEST_PLAN.md` for full validation evidence.

## Repository hygiene finding (pre-existing, fixed)

The repository had `.gradle/` build-cache directories, compiled `.class` files, the built
`.jar`, and `.DS_Store` files committed to git, **with no root `.gitignore` at all**. There was
also a leftover nested `ClientSideEye-Burp/` directory (containing nothing but another stale
`.gradle/` cache, a `.gitignore`, and a `.DS_Store` — no source) that appears to be debris from
an earlier repository rename. This bloats the repository, produces noisy diffs on every commit,
and risks shipping stale/inconsistent binary artifacts. **Fixed**: added `.gitignore`; deleted
the cache/output directories and the stray nested project folder from the working tree (the user
should `git add -A` / commit these removals when ready — no commit was made by this review per
instructions).

## Architecture assessment

- **Separation of concerns is good** for a project this size: pure static-analysis logic
  (`HtmlAnalyzer`, `JavaScriptAnalyzer`, `SourceMapAnalyzer`, `FindHintBuilder`, `JsonExporter`)
  is fully Burp-independent (no Montoya imports), which is exactly what makes most of it
  unit-testable without launching Burp. `ClientSideEyeExtension`/`ClientSideEyeTab`/
  `BrowserBridgeServer` are the only Burp/Swing-integrated classes.
- **No circular dependencies, no god classes** in the analyzer package. `ClientSideEyeTab.java`
  (879 lines) is the largest file and does carry multiple responsibilities (filter UI, table
  model, Site Map scan orchestration, dialogs, clipboard, JSON export) — it is not yet a "god
  class" problem in practice, but if more finding types or UI panels are added it should be
  split (e.g. extract `SiteMapScanner` and `FindingsTableModel` into their own top-level
  classes) before it grows further.
- **`Finding` is a reasonable value-ish class** (final fields, defensive `null`→`""` coercion,
  clamped confidence) but is not a `record`. Given it already existed with multiple
  constructor overloads for backward compatibility (used by tests and `BrowserBridgeServer`),
  converting it to a record was **not** done in this pass — it would touch every call site for
  a purely cosmetic gain and the current class is already effectively immutable.
- **Dead/leftover code:** none found of note. `Finding`'s three constructor overloads are all
  actually used (by tests, by analyzers, and by the bridge). No unused imports or obviously
  dead branches were found in the reviewed files.
- **Testability without launching Burp:** good for the analyzer classes (already had dedicated
  JUnit tests with zero Burp dependency). `BrowserBridgeServer` needed Mockito to stand up a
  `MontoyaApi` double for its new network-level regression tests — this is a reasonable,
  minimal addition rather than over-engineering, since hand-writing a `MontoyaApi` stub by
  implementing every method would be far more code than the tests it enables.

## Maintainability concerns (not fixed — recommendations only)

- `ClientSideEyeTab.java`'s `analyzeSiteMapInScope` and the type/severity filter checkboxes use
  a lot of repetitive boilerplate (11 `JCheckBoxMenuItem` type filters wired up almost
  identically). Extracting a small `TypeFilter` record/list-driven loop would reduce
  duplication and the chance of forgetting to wire up a new `FindingType` in the future (a real
  risk: adding a new `FindingType` today requires touching `FindingType.java`,
  `ClientSideEyeTab`'s field list, `typeMenu.add(...)`, listener wiring, and `selectedTypes()`
  in four separate places).
- `HtmlAnalyzer.scoreControlSignals` is a large, heavily-weighted heuristic scoring function
  with magic numbers (`+=30`, `+=15`, `>= 60`, etc.) and no named constants. It works and is
  covered by tests for the cases that matter, but tuning it further will be error-prone without
  extracting the weights into named constants with comments explaining each signal's rationale.
- `JavaScriptAnalyzer`'s and `HtmlAnalyzer`'s regex-based endpoint/route detection
  (`ENDPOINT_PATTERN`, `ROUTE_PATTERN`) will produce a meaningful false-positive rate on large
  minified bundles (e.g. matching quoted strings that are CSS selectors, i18n keys, or SVG path
  data that happen to start with `/`). This is a detection-quality/noise concern, not a
  correctness bug — see `Detection quality` notes below.
- `push.sh`-style personal tooling should live outside the versioned repository (e.g. in a
  private dotfiles repo) rather than being deleted-and-forgotten; flagging this so the
  maintainer can relocate rather than lose the workflow.

## Reliability

- **Fixed in this review:** single-item failures no longer abort an entire batch/Site Map scan
  (see change #8 above).
- `BrowserBridgeServer.handleClient` already had a top-level `catch (Exception e)` that logs
  and does not crash the accept loop — good defensive design, retained as-is.
- `ClientSideEyeExtension.initialize` wraps `bridgeServer.stop()` and `bg.shutdownNow()` in the
  unloading handler with `catch (Exception ignored)` — acceptable for best-effort cleanup on
  unload, though swallowing the exception silently means a cleanup failure would be invisible.
  Given this only runs once at unload time, low risk; **not changed**, but consider at least a
  `logToError` there in a future pass.

## Performance

- No profiling was performed (no concrete performance problem was reported or observed at the
  data volumes exercised in testing). The `MAX_FINDINGS = 5000` cap, single-thread background
  executor, and lack of full-history rescans on every event are all reasonable defaults for the
  target usage pattern (interactive, user-triggered analysis, not a continuous background scan).
- The one theoretical concern — a user-configurable Site Map scan of up to `SITE_MAP_SCAN_HARD_CAP`
  (2000, adjustable up to 10000 via the spinner) items running on a single background thread
  with no cancellation button — is a responsiveness/UX limitation rather than a performance bug;
  see `TEST_PLAN.md` for a manual test to characterize actual runtime on a large project.

## Deferred recommendations (not implemented — out of scope for a minimal, reviewable change set)

1. Add a "Cancel scan" affordance for long-running Site Map scans (currently only a
   pre-scan confirmation dialog exists; there is no way to abort mid-scan).
2. Extract `ClientSideEyeTab`'s type/severity filter wiring into a data-driven loop to reduce
   duplication and the risk of missing a wire-up when adding a new `FindingType`.
3. Consider tightening the JS/HTML "looks like" heuristics further with a small allow-list of
   known non-code content types (e.g., explicit `Content-Type`-aware gating if/when this
   extension is given access to response headers) to reduce false positives on large minified
   bundles, without reintroducing the false-negative regression fixed in this review.
4. Consider converting `Finding` to a `record` in a future major version bump (breaking change
   for the multiple constructor overloads currently in use).

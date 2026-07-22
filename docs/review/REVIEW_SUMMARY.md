# ClientSideEye — Review Summary

## Addendum 2: final pre-submission check (2026-07-22)

A final validation pass was run after all UI/detection fixes in Addendum 1 below. Scope: clean
build, full test suite, JAR inspection, a targeted dependency-currency check, and a full
`git status`/`git diff` sweep of the actual repository state (as opposed to just the working
tree contents).

**Dependency currency (checked, not blindly bumped):**
- Bumped `montoya-api` `2025.12` → **`2026.7`** (current release as of this check) and jsoup
  `1.18.3` → **`1.22.2`** (current release). Checked jsoup's GitHub security advisories first:
  the one *High* advisory (GHSA-m72m-mhq2-9p6c, parser DoS on crafted input) was fixed well
  before `1.18.3`; the one *Moderate* advisory (Cleaner/Safelist XSS bypass) does not apply,
  since this codebase never uses `Cleaner`/`Safelist`. Both bumps are therefore precautionary
  currency, not fixes for a live vulnerability. Verified `./gradlew clean build` compiles and
  **all 50 tests still pass** with both new versions before keeping the change (no Montoya API
  usage in this codebase touches anything that changed between `2025.12` and `2026.7`).
- Re-confirmed via `jar tf`: no `montoya` classes bundled in the built jar; jsoup is correctly
  bundled (it's the only non-Burp-provided runtime dependency, and Burp does not supply it).

**Critical finding — the actual GitHub repository does not yet reflect this review:**
`git --no-optional-locks status` shows that **nothing from this review (or the follow-up
rounds after it) has been committed.** The repository at `origin/main`, if checked out fresh
right now, would still contain:
- 22 tracked files under `build/` and 13 under `.gradle/` (compiled `.class` files and Gradle
  build-cache internals — must never be version-controlled).
- 15 tracked files under a stray nested `ClientSideEye-Burp/` duplicate project directory.
- The old `push.sh` helper script, which is **still live in the committed `HEAD`** and discloses
  a personal local path (`$HOME/Tools/ClientSideEye-Burp/...`), a personal git remote alias, and
  a GitHub handle. Deleting the file from the working tree (already done) has no effect on the
  public repository until this deletion is actually committed — and even after that commit, the
  content remains visible in the repository's git history unless that history is rewritten.
- An orphaned, stale `ClientSideEye-Burp-0.1.0.jar` (superseded by `0.2.0`).
- None of the actual security/detection/UI fixes, the Gradle wrapper, the CI workflow,
  `SECURITY.md`, or this `docs/review/` folder — all of it exists only in the local working
  tree.

This is the single highest-priority item before submission: **the code-level work in this
review is only real once it is committed (and pushed, if submitting the GitHub URL to
PortSwigger).** No commit was made as part of this or any prior round, per standing instructions
not to commit without explicit request. See "Remaining blockers" below.

**Other findings from this pass:**
- `LICENSE` and `settings.gradle` had their file mode accidentally flipped to executable
  (`100644` → `100755`) at some point in earlier tooling; reset back to `100644` (non-executable
  is correct for a license text file and a Gradle settings file).
- `LICENSE` is MIT, compatible with jsoup's own MIT license — no license conflict.
- No hardcoded secrets, API keys, or credential-shaped strings found anywhere in the repository
  (tracked or untracked) via a targeted pattern sweep (AWS keys, PEM private key headers, GitHub
  tokens, Slack tokens, generic certificate blocks).
- `README.md` was diffed against actual current behavior line-by-line; it accurately reflects
  the bridge-token flow, the "Find Hint" button naming, the current finding-type list, and the
  external-script/source-map fetching behavior added in later rounds.

Final state after this check: **50/50 tests passing**, clean build via `./gradlew clean build`,
jar contents re-verified clean, dependencies bumped to current releases and re-validated.
Version remains `0.2.0` (no functional change in this pass, only dependency currency + repo
hygiene review).

## Addendum 1: follow-up improvements round (same review session)

After the initial fix pass documented below, a second round of maintainer-approved
improvements was implemented. The "Bridge opt-in" recommendation was explicitly declined by
the maintainer, since it would undermine the extension's core purpose of seeing client-side
state that raw packet capture cannot show.

- Fixed an O(n^2) EDT-refresh storm in Site Map/right-click batch analysis by batching findings
  before updating the table instead of refreshing once per matched item.
- Added three new detection capabilities to `JavaScriptAnalyzer`: framework-specific HTML sinks,
  a new `PROTOTYPE_POLLUTION_HINT` finding type, and hard-coded `WebSocket`/`EventSource`
  endpoint detection (`RUNTIME_NETWORK_REFERENCE`), each with regression tests and full UI
  filter wiring.
- Extracted `FindingsTableModel` from a private inner class into a standalone,
  dependency-injected top-level class and added a dedicated unit test suite.
- Added accessibility improvements (`setLabelFor`) and header tooltips clarifying that
  "Confidence" is a heuristic signal count, not a probability.
- Added best-effort persistence (Montoya `Preferences`) for host filter, scan limit, and
  export-visible-only settings.
- Added a committed Gradle wrapper and a GitHub Actions CI workflow.
- Added `SECURITY.md` with a vulnerability-disclosure process.
- Brought `README.md`'s "Finding Types" list fully up to date.
- Fixed several "View in Browser..." UX/correctness bugs found during live testing against a
  companion test lab: a dialog-width bug and a Find-Hint copy-corruption bug (both caused by
  concatenating labels and multi-line JS snippets into a single string), Highlight Snippet not
  visibly doing anything when the target is inside a hidden ancestor container, Reveal Snippet
  not unmasking `<input type="password">` values, and the three snippet-action buttons having no
  visual separation from each other.
- Generalized Reveal/Highlight Snippet so their disabled/hidden-state override logic is
  pattern-based (matches naming conventions across CSS frameworks) and applies `!important`
  style overrides driven by `getComputedStyle(...)`, rather than a curated list of exact class
  names and non-important inline styles that only reliably worked against one tested
  application.
- Brought the Browser Bridge's runtime scanner (`popup.js`) to full parity with the Java-side
  analyzers (6 of 12 finding types were previously missing from the browser path), and added
  bounded fetching of external script bodies and referenced source maps from the page's own
  context so the browser scanner can see content that never appears in the live DOM.
- Fixed a real, non-app-specific regex word-boundary bug shared by both the Java analyzer and
  the browser scanner that caused `ROLE_PERMISSION_HINT`/`INLINE_SCRIPT_SECRETISH` to never
  match underscore-prefixed or camelCase identifiers.
- Fixed the companion browser extension popup's three buttons having no CSS margin between them
  at all, and visually grouped the two scan actions separately from the one-time setup action.

Final state after this round: **50/50 tests passing**, clean build via both system Gradle and
the `./gradlew` wrapper, jar contents verified clean. Version bumped to `0.2.0`.

## Original review (first round)

## Important scoping note

At the start of this review, `git status`/`git diff` already showed a large number of files
with **pre-existing, uncommitted local modifications** (e.g. `FindHintBuilder.java`,
`Finding.java`, `FindingType.java`, `JsonExporter.java`, `README.md`,
`browser-extension/clientsideeye-bridge/popup.js`, and others) — this was the maintainer's own
work-in-progress sitting in the working tree before this review began, not something introduced
by this review. All analysis and fixes in this review were performed against the actual
on-disk state (i.e., including that pre-existing WIP), which is the correct basis for review.
The **"Files changed"** table below lists only the files this review itself created or
modified, distinguished from that pre-existing drift.

## Overall risk rating

**Medium**, driven primarily by one now-fixed High-severity UI/HTML-injection issue
(`SEC-01`) and one now-fixed Medium-severity local-DoS issue (`SEC-02`) in the Browser Bridge.
With those fixed, residual risk is Low: the extension makes no outbound network calls, has a
narrow and disclosed local-only attack surface, and has no dependency, deserialization,
reflection, or command-execution red flags anywhere in the codebase.

## Overall engineering maturity

**Solid-but-uneven.** The core analyzer package (`HtmlAnalyzer`/`JavaScriptAnalyzer`/
`SourceMapAnalyzer`/`FindHintBuilder`) is genuinely Burp-independent, already had a reasonable
existing test suite, and uses a real HTML parser (jsoup) rather than regex-only tag matching —
better practice than many BApps of this size. The Burp/Swing integration layer
(`ClientSideEyeTab`, `BrowserBridgeServer`) is functional and mostly follows Burp's documented
threading/GUI-parenting guidance correctly, but had accumulated some real defects (detection
false negatives, batch-abort-on-first-error, unbounded local-listener reads, missing HTML-render
guards) consistent with fast iterative feature growth without an accompanying hardening pass —
exactly the kind of gap a pre-submission review is supposed to catch.

## Top 5 risks (before this review's fixes)

1. **`SEC-01`** — Attacker-influenced finding text could trigger real HTML rendering (including
   outbound `<img>` requests) inside Burp's Swing UI. **Fixed.**
2. **`SEC-02`** — The local Browser Bridge's hand-rolled HTTP parser had no line-length or
   header-count bound, allowing local memory exhaustion. **Fixed.**
3. **Detection false negatives** — Two independent, overly-strict heuristic gates
   (`HtmlAnalyzer.looksLikeHtmlForAnalysis`, `JavaScriptAnalyzer.looksLikeJavaScriptForAnalysis`)
   silently dropped entire classes of real findings, undermining the tool's core purpose.
   **Fixed**, with regression tests.
4. **Batch-abort-on-first-error** — A single malformed/adversarial response could silently
   truncate analysis of an entire multi-item Site Map scan or right-click selection.
   **Fixed.**
5. **Repository hygiene** — Committed build caches/output, a stray duplicate directory, and a
   personal-path/personal-identity release script. Not a security vulnerability in the
   extension itself, but a real blocker to a clean, professional public submission. **Fixed in
   the working tree; not yet committed — see Addendum 2 above, this is now the top blocker.**

## Top 5 improvements made (this review)

1. Force-disabled Swing HTML interpretation on all renderers that display finding-derived text
   (`SeverityRowRenderer`, Find-Hint combo box renderer).
2. Added a bounded-line/bounded-header-count HTTP parser in `BrowserBridgeServer`, with a new
   end-to-end socket-level regression test suite.
3. Fixed two independent detection-false-negative regressions and added regression tests for
   each; also fixed a third (hidden interactive `<div>`/`<span>` controls being silently
   dropped).
4. Isolated per-item failures inside both batch-analysis loops so one bad item no longer aborts
   the rest of the batch.
5. Cleaned up repository hygiene: added `.gitignore`, removed committed build artifacts and a
   duplicate stray directory, removed a personal-path/identity-leaking script, fixed a Gradle
   9-incompatibility that made `gradle test` fail outright on a clean checkout, and bumped/
   documented a `0.1.1` fix release.

## Tests and tools executed

- `gradle -v` — recorded environment (Gradle 9.4.0, Java 17 toolchain, macOS host).
- `gradle clean build` / `gradle clean test` — run multiple times throughout this review;
  final state as of Addendum 2: **50/50 tests passing**, jar builds successfully.
- `unzip -l`/`unzip -p`/`jar tf` on the built jar — used repeatedly to confirm Montoya API
  classes are absent, jsoup classes are present, Mockito is absent, and the manifest is
  minimal/correct.
- `git --no-pager diff` / `git --no-optional-locks status` — used throughout to distinguish
  this review's changes from pre-existing working-tree drift (see scoping note above), and, in
  Addendum 2, to confirm the actual committed state of the repository.
- A targeted secret-pattern sweep (`grep` for AWS keys, PEM private key headers, GitHub/Slack
  tokens, certificate blocks) across the entire repository — Addendum 2 — no matches.
- A jsoup GitHub Security Advisories review — Addendum 2 — confirmed no unpatched advisory
  applies to this codebase's usage.
- **Not run / not available in this environment:** SpotBugs, PMD, Checkstyle, Semgrep, CodeQL,
  OWASP Dependency-Check, OSV Scanner, JaCoCo, ArchUnit, a live Burp Suite instance, and any
  performance/load profiling against a real large Site Map. All of these are disclosed as not
  run in `TEST_PLAN.md` rather than assumed clean.

### Recommended minimal toolchain for this project going forward

Given the project's size (~2,800 lines of main source as of Addendum 2), a heavyweight
static-analysis stack would be disproportionate. Recommended minimal additions: **SpotBugs +
the Find Security Bugs plugin** (catches exactly the class of Swing/network/resource-handling
issues found manually in this review, going forward) and **JaCoCo** (coverage visibility for
the analyzer package, which is the highest-value code to keep well-tested). Not adding
PMD/Checkstyle/Semgrep/CodeQL at this project's current size — they would add configuration
burden disproportionate to the benefit right now.

## Files changed by this review

| File | Change type | Summary |
|---|---|---|
| `.gitignore` | Added | New root-level gitignore (build output, OS metadata, IDE files) |
| `build.gradle` | Modified | Added `junit-platform-launcher`, Mockito + test-scoped montoya-api dependency; version bumps; dependency currency bump (Addendum 2: montoya-api `2026.7`, jsoup `1.22.2`) |
| `build.sh` | Modified | Removed hardcoded stale jar filename |
| `push.sh` | **Deleted (working tree only — still committed in `HEAD`, see Addendum 2)** | Removed personal-path/personal-identity release helper script |
| `CHANGELOG.md` | Modified | Documented each fix release |
| `src/main/java/com/clientsideeye/burp/ClientSideEyeExtension.java` | Modified | Per-item try/catch isolation in the right-click batch handler |
| `src/main/java/com/clientsideeye/burp/core/HtmlAnalyzer.java` | Modified | Broadened HTML-detection gate; fixed hidden-`<div>`/`<span>` drop; regex word-boundary fixes; framework XSS sinks; prototype-pollution detection; all with regression tests |
| `src/main/java/com/clientsideeye/burp/core/JavaScriptAnalyzer.java` | Modified | Broadened JS-detection gate; added ungated `analyzeJavaScriptContent`; WebSocket/EventSource detection; regression tests |
| `src/main/java/com/clientsideeye/burp/core/SourceMapAnalyzer.java` | Modified | Use ungated JS analysis for known-JS `sourcesContent` |
| `src/main/java/com/clientsideeye/burp/integration/BrowserBridgeServer.java` | Modified | Bounded line/header reads (`SEC-02` fix) |
| `src/main/java/com/clientsideeye/burp/ui/ClientSideEyeTab.java` | Modified | `html.disable` on table/combo renderers (`SEC-01` fix); per-item try/catch isolation; batched table refresh; persisted preferences; accessibility improvements; "View in Browser..." dialog UX fixes and button spacing/tooltips |
| `src/main/java/com/clientsideeye/burp/ui/FindHintBuilder.java` | Modified | Structured `HintEntry` (fixes dialog width + copy-corruption bugs); ancestor-reveal in Highlight Snippet; password-unmask in Reveal Snippet; pattern-based/`!important` disabled-hidden-state overrides |
| `src/main/java/com/clientsideeye/burp/ui/FindingsTableModel.java` | **Added** | Extracted from a private inner class into a standalone, dependency-injected top-level class |
| `browser-extension/clientsideeye-bridge/popup.js` | Modified | Full parity with Java-side finding types; external script/source-map fetching; regex word-boundary fixes |
| `browser-extension/clientsideeye-bridge/popup.html` | Modified | Button spacing/visual grouping fix |
| `browser-extension/clientsideeye-bridge/manifest.json` | Modified | Added `storage` permission for the bridge-token feature |
| `src/test/java/com/clientsideeye/burp/core/HtmlAnalyzerTest.java` | Modified | Regression tests for the HTML-gate fix and subsequent detection fixes |
| `src/test/java/com/clientsideeye/burp/core/JavaScriptAnalyzerTest.java` | **Added** | Regression tests for the JS-gate fix and subsequent detection additions |
| `src/test/java/com/clientsideeye/burp/core/SourceMapAnalyzerTest.java` | **Added** | Regression tests for source-map analysis |
| `src/test/java/com/clientsideeye/burp/ui/FindHintBuilderTest.java` | Modified | Regression tests for every "View in Browser..." fix described above |
| `src/test/java/com/clientsideeye/burp/ui/FindingsTableModelTest.java` | **Added** | Unit tests for the extracted table model |
| `src/test/java/com/clientsideeye/burp/integration/BrowserBridgeServerNetworkTest.java` | **Added** | New socket-level regression tests for the `SEC-02` fix |
| `src/test/java/com/clientsideeye/burp/integration/BrowserBridgeServerTest.java` | **Added** | Integration tests for the Browser Bridge |
| `ClientSideEye-Burp-0.1.0.jar` | **Deleted (working tree only — still committed in `HEAD`, see Addendum 2)** | Stale committed build artifact |
| `ClientSideEye-Burp-0.2.0.jar` | **Added (working tree only, not yet committed)** | Rebuilt convenience jar matching current source and current dependency versions |
| `.gradle/`, `build/`, `ClientSideEye-Burp/` (nested dir), `.DS_Store` | **Deleted (working tree only — still committed in `HEAD`, see Addendum 2)** | Removed committed build caches/output and stray duplicate project directory |
| `gradlew`, `gradlew.bat`, `gradle/` | **Added (untracked)** | Committed Gradle wrapper for reproducible builds |
| `.github/workflows/build.yml` | **Added (untracked)** | CI workflow: build + test + upload jar/test-report artifacts on every push/PR |
| `SECURITY.md` | **Added (untracked)** | Vulnerability disclosure process |
| `docs/review/*.md` (7 files) | **Added (untracked)** | This review's deliverables |
| `LICENSE`, `settings.gradle` | File-mode fix only | Reset accidental executable bit (`100755` → `100644`) |

**Not modified by this review** (pre-existing local working-tree changes present before this
review began, per the scoping note above): `src/main/java/com/clientsideeye/burp/core/Finding.java`,
`FindingType.java`, `JsonExporter.java`.

## Remaining blockers before PortSwigger submission

1. **Commit and push this review's changes.** This is now the top blocker: as of Addendum 2,
   nothing described in this document has actually been committed. The public GitHub
   repository, if fetched fresh right now, would not reflect any of this work and would still
   contain committed build artifacts, a stray duplicate directory, and a personal-path/identity
   -leaking script. Recommend committing in a small number of logical groups (e.g. "repo
   hygiene", "security fixes", "detection fixes", "UX fixes", "docs/CI") rather than one giant
   commit, then pushing to `origin/main`.
2. Perform the manual Burp-instance tests in `TEST_PLAN.md` §2 (load, repeated unload/reload,
   large Site Map, Browser Bridge end-to-end, per-item-failure isolation). Note: extensive
   manual testing against a companion test lab *was* performed during Addendum 1's follow-up
   round (informing several of the fixes above), but the formal checklist in `TEST_PLAN.md` §2
   has not been run end-to-end as a single pass.
3. Search the live BApp Store for overlapping extensions immediately before submission.
4. State the minimum supported Burp Suite version corresponding to Montoya API `2026.7` in the
   listing (cross-check against your own Burp installation's version history).
5. Decide how to handle the fact that `push.sh`'s personal-path/identity content will remain in
   git history even after being removed from `HEAD`, unless history is rewritten (e.g.
   `git filter-repo`) before making the repository public, or unless the repository is already
   private/new enough that this isn't a practical concern.

## Final recommendation

**Ready after minor fixes** — specifically, committing and pushing the working-tree state
described above. The concrete, code-level blockers identified across both rounds of this review
(HTML injection, local-DoS, detection false negatives, batch-abort-on-error, repository hygiene,
UX bugs found during live lab testing, dependency currency) have all been fixed and validated by
a clean build with all 50 tests passing. What remains is (a) actually committing/pushing this
work so the public repository reflects it, and (b) manual verification that requires a live Burp
Suite instance and access to the live BApp Store catalog — neither of which is available in this
review environment. No further code changes are believed necessary based on this review's
findings.

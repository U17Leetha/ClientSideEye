# Production hardening

## Scope and baseline

Start from U17Leetha/ClientSideEye main at 0ebf4c9e65852ba4c167d9fdd27bc943c3937955, retaining its detection/UI changes. The old MAIN-world runtime-hook implementation is absent upstream and must not be restored.

ClientSideEye-Lab is an intentionally vulnerable fixture and is outside this change. Existing local changes are preserved in /private/tmp/extension-pre-hardening-20261026 and the ClientSideEye pre-authoritative-sync-20261026 Git stash.

## Decisions

- Bound network workers, accepted sockets, request bytes, headers, body size and absolute read duration. Authenticate finding bodies before reading them. Close accepted sockets on unload and reject unsupported HTTP framing explicitly.
- Keep loopback-only listeners. Preserve a working PoC until a replacement binds successfully.
- Bound response bytes before decoding, source-map nesting/content counts, HTML nodes/depth and result counts. Surface budget failures rather than silently claiming complete analysis.
- Use Gson 2.13.2 (Apache-2.0) for strict, depth-limited source-map JSON parsing and JavaScript string serialization; preserve source array positions. This replaces custom JSON decoding rather than adding generic infrastructure.
- Keep label and executable hint values separate. Resolve only exact attribute/text predicates across accessible roots; perform mutations only after unambiguous resolution. Untrusted values enter generated JavaScript through one serialization boundary.
- Use complete finding identities, preserve first-seen values and prune evicted triage state. Snapshot scan options on the EDT and invalidate stale result batches on clear.
- Probe product identity without credentials, then authenticate the selected bridge session. Never log bearer tokens.
- Keep source/version/artifact provenance explicit and preserve supported routes and finding types. Remove only unused supported code; archive local historical files rather than deleting user data.

## Verification

Run Gradle check/build, Java HTTP wire tests, executed generated-JavaScript tests in Node, adversarial Bash HTML-output tests, browser collector tests, dependency audit, and diff whitespace checks. Include hostile quote/newline/Unicode inputs, source-map null slots and duplicates, duplicate/invalid headers, stalls, unload and occupied ports. A real-browser smoke test should verify DOM targeting when tooling is available. Run a security review before committing. Do not publish or ship without the operator review boundary.

## Failure modes and tradeoffs

Bounded scans may reject very large inputs; report limits and let the operator narrow the selection. The bridge remains automatically available as required by upstream. CORS is not authentication. Any browser observation remains untrusted evidence requiring manual validation. Keep security-sensitive helpers small and purpose-specific instead of introducing service layers.

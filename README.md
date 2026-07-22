# ClientSideEye (Burp Extension)

ClientSideEye is a Burp Suite extension for identifying **client-side security anti-patterns**
such as hidden/disabled privileged controls and passwords rendered in HTML responses.

## Quick Start (60 seconds)

1. Build and load extension JAR in Burp:
   - `gradle clean jar`
   - Burp `Extensions -> Installed -> Add` (Java), select built JAR
2. Confirm Burp output shows:
   - `[ClientSideEye] Browser bridge listening on http://127.0.0.1:<port> ...`
   - `[ClientSideEye] Browser bridge token: <token>`
3. Load unpacked browser bridge extension from:
   - `browser-extension/clientsideeye-bridge/`
4. In the Burp `ClientSideEye` tab, copy the displayed **Bridge Token**
5. Paste the token into the browser extension popup and click **Save Bridge Token**
6. Open target page, click browser extension button:
   - `Scan Current Tab + Send to ClientSideEye`
   - or `Watch DOM For 15s + Send` for SPA/runtime changes
7. In popup, confirm:
   - `Bridge: http://127.0.0.1:<port>`
   - `Sent: <n>`
8. Open Burp `ClientSideEye` tab and triage findings.

## Browser Extension Setup

ClientSideEye includes a companion Chromium browser extension in:

- `browser-extension/clientsideeye-bridge/`

Load it as an unpacked extension, then click:

- `Scan Current Tab + Send to ClientSideEye`

The popup should show:

- `Bridge: http://127.0.0.1:<port>`
- `Sent: <n>`

The popup now requires a per-session **Bridge Token** from the Burp extension tab.

## Features
- Detects plaintext password values in HTML
- Identifies hidden/disabled actionable UI controls
- Scores findings by severity and confidence
- Highlights high-risk issues in the UI
- Provides browser-friendly “find hints” for rapid validation
- Detects common DevTools blocking/detection logic and provides a bypass snippet
- Scans JavaScript for endpoint references, DOM XSS sinks, and postMessage usage
- Detects source map references and analyzes exposed `.js.map` responses
- Extracts runtime signals from the browser extension including storage tokens and inline script indicators
- Enumerates runtime network/API references from the browser using `performance` resource data
- Exports findings as JSON
- Analyzes in-scope Site Map traffic
- Accepts runtime DOM findings via localhost Browser Bridge (for SPA/hash-route pages)
- Uses parsed HTML analysis via jsoup rather than regex-only tag matching
- Supports live search, host-scoped Site Map scans, and export of visible rows only

## Installation

### Recommended


1. Download the latest ```ClientSideEye-Burp.jar```
2. In Burp Suite:

- Extensions → Installed → Add

- Extension type: Java

- Select the generated JAR

### Build from source
1. Build the extension:
   ```bash
   gradle clean jar
   ```

## Usage

1. Browse the target application normally

2. Open the ClientSideEye tab

3. Click **Analyze Site Map (in-scope)** or use right-click send-to from Proxy/HTTP History

4. Triage findings by Severity and Confidence
<img width="1501" height="855" alt="image" src="https://github.com/user-attachments/assets/e3b67ed3-7893-4cf0-84a0-a0c50a0b4a99" />

Notes:
- `Host filter` now also scopes Site Map scans when set.
- `Search` filters across title, type, URL, evidence, and finding identity.
- `Export visible rows only` exports the currently filtered set rather than the entire store.
- Site Map and right-click analysis now inspect both HTML responses and JavaScript assets when they look analyzable.
- JavaScript assets with `sourceMappingURL` comments and exposed `.js.map` responses are analyzed for extra client-side attack surface.

5. Use View in Browser to validate findings
<img width="901" height="553" alt="image" src="https://github.com/user-attachments/assets/8ecc53e8-7bb3-4c67-b7cb-1c46e8870c54" />
### Validating Findings in the Browser

For each finding, ClientSideEye provides browser-friendly **Find Hints** to help you quickly locate the affected element in the DOM.

1. Select a finding in the **ClientSideEye** tab.
2. Click **View in Browser…**.
3. Click **Find Hint** (copies the selected hint to your clipboard).
4. Paste the hint into your browser’s DevTools:
   - **Firefox**: Paste into the **Console** (recommended) or use it as a text search in the **Inspector**.
   - **Chrome/Chromium**: Paste into the **Console** or use it directly in the **Elements** search.

The Inspector will jump directly to the relevant element, allowing you to:
- Unhide or re-enable controls
- Inspect attributes and event handlers
- Manually validate whether server-side authorization is enforced

Notes:
- Find Hints now prefer `data-testid` when present (before generated IDs).
- Reveal snippet clears disabled/hidden state generically rather than targeting one framework:
  it removes `disabled`/`aria-disabled`/`hidden` attributes, strips any CSS class whose name
  matches a disabled/hidden naming pattern (covers Bootstrap, PatternFly, Ant Design, Material
  UI, Bulma, and hand-rolled conventions), overrides `display`/`visibility`/`opacity`/
  `pointer-events` with `!important` so it also beats `!important` utility classes (e.g.
  Bootstrap's `.d-none`/`.invisible`), and switches matched `<input type="password">` fields to
  `type="text"` so the plaintext value becomes visible.
- Highlight snippet also temporarily un-hides any hidden *ancestor* container so the outline is
  actually visible, without changing the target control's own disabled/hidden state.
- In "View in Browser...", the Highlight/Reveal/DevTools-bypass action rows are visually grouped
  together below a divider, with a specific tooltip on each button describing what it does.

## Finding Types

- PASSWORD_VALUE_IN_DOM
- HIDDEN_OR_DISABLED_CONTROL
- ROLE_PERMISSION_HINT
- INLINE_SCRIPT_SECRETISH
- DEVTOOLS_BLOCKING
- JAVASCRIPT_ENDPOINT_REFERENCE
- DOM_XSS_SINK (including framework-specific sinks: `dangerouslySetInnerHTML`, Angular `[innerHTML]`/`bypassSecurityTrust*`, Vue `v-html`)
- POSTMESSAGE_HANDLER
- STORAGE_TOKEN (Browser Bridge only)
- SOURCE_MAP_DISCLOSURE
- RUNTIME_NETWORK_REFERENCE (hard-coded `WebSocket`/`EventSource` endpoints, plus Browser Bridge runtime resource data)
- PROTOTYPE_POLLUTION_HINT (`__proto__` access, unguarded `merge`/`extend`/`Object.assign` of parsed data)

All finding types above are produced by both the Java-side Site Map/right-click analysis and the
Browser Bridge's runtime scanner - the two paths have full parity.

## Browser Bridge (for Runtime DOM Findings)

ClientSideEye starts a local bridge server at:

- `http://127.0.0.1:<port>/api/health`
- `http://127.0.0.1:<port>/api/finding`

This lets an external browser extension or CLI submit findings from rendered DOM state (useful for SPA/hash routes where controls are not present in raw HTTP HTML).

Bridge port behavior:
- Default port is `17373`.
- If busy, ClientSideEye automatically tries `17374` to `17382`.
- Active port is logged in Burp extension output.
- A per-session bridge token is generated on startup and shown in the Burp tab/output.

### POST format

`Content-Type: application/x-www-form-urlencoded`

Required:

- `url`

Optional:

- `type` (defaults to `HIDDEN_OR_DISABLED_CONTROL`)
- `severity` (`HIGH|MEDIUM|LOW|INFO`, default `MEDIUM`)
- `confidence` (0-100, default `55`)
- `title`
- `summary`
- `evidence`
- `recommendation`
- `source`

Example:

```bash
curl -X POST "http://127.0.0.1:17373/api/finding" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "source=manual-test" \
  --data-urlencode "url=https://example.test/app#/settings" \
  --data-urlencode "type=HIDDEN_OR_DISABLED_CONTROL" \
  --data-urlencode "severity=MEDIUM" \
  --data-urlencode "confidence=75" \
  --data-urlencode "title=Client-side disabled save control in rendered DOM" \
  --data-urlencode "summary=Save action was disabled client-side and could be re-enabled in DevTools." \
  --data-urlencode "evidence=<button data-testid='save' aria-disabled='true' disabled>Save</button>"
```

### Included starter browser extension

A starter Chromium extension is included at:

- `browser-extension/clientsideeye-bridge/manifest.json`
- `browser-extension/clientsideeye-bridge/popup.html`
- `browser-extension/clientsideeye-bridge/popup.js`

It scans the current tab for actionable disabled/hidden controls and posts findings to the local bridge.

The popup also provides `Watch DOM For 15s + Send`, which repeatedly snapshots the active tab to catch SPA route changes and delayed rendering.

Runtime browser collection now also looks for:

- token- or secret-like values in `localStorage` / `sessionStorage`
- endpoint references in inline/runtime scripts
- dangerous DOM/code-execution sinks such as `innerHTML` and `eval` (including framework-specific
  sinks like React `dangerouslySetInnerHTML`, Angular `[innerHTML]`/`bypassSecurityTrust*`, and
  Vue `v-html`)
- `postMessage` usage patterns
- runtime network/API requests referenced by `fetch`, XHR, scripts, and other observed resources
- role/permission hints, secret-like inline script values, DevTools blocking/detection logic,
  hard-coded `WebSocket`/`EventSource` endpoints, and prototype-pollution patterns

### Fetching external scripts and source maps

Externally-loaded `<script src="...">` tags never expose their body through the DOM
(`textContent` is empty for them), so the browser scanner fetches a bounded number of them
itself (up to 5 per scan, 1.5s timeout each, ~400KB size cap) to analyze their content the same
way as inline `<script>` bodies. If a fetched script references a source map
(`//# sourceMappingURL=...`), the scanner also fetches that map (up to 3 per scan, same bounds),
parses it, and recursively analyzes any embedded original source in `sourcesContent` - source
maps frequently contain the full unminified original code, which can surface findings that are
much harder to spot in the shipped minified bundle.

These fetches:
- are issued from the **page's own context** (same-origin, using the page's own
  cookies/permissions, exactly like the page's own JavaScript would), not from the extension's
  privileged context - no additional `host_permissions` are required.
- fail silently and are skipped (never abort the rest of the scan) on network errors, CORS
  blocks, timeouts, or oversized responses.
- are the only outbound network activity this browser extension performs beyond talking to the
  local ClientSideEye bridge - no fetch ever leaves the current page's own origin/network path.

## Security Model

The Browser Bridge is intentionally bound to `127.0.0.1` only.

To reduce the risk of arbitrary web pages injecting spoofed findings into Burp:

- `POST /api/finding` requires a per-session bridge token
- CORS is only granted to browser extension origins
- request bodies are size-limited
- bridge sockets use read timeouts and worker handling to avoid a single stalled client blocking the bridge

## SPA/Hash Route Guidance

For routes like:

- `https://target/app/#/settings/localization`

the `#/...` fragment is client-side routing and often does not exist as a discrete server URL in Site Map.

Use one of these:
- Browser Bridge (recommended): send runtime DOM findings directly to ClientSideEye.
- Proxy/HTTP History send-to for underlying API responses and shell HTML.

## Troubleshooting

### Browser bridge port in use

If logs show:

- `Default port 17373 was busy. Using fallback port 17374.`

this is expected. Reload the browser bridge extension so it can probe the active port.

### Browser extension not sending findings

1. Confirm Burp output includes:
   - `Browser bridge listening on http://127.0.0.1:<port> ...`
   - `Browser bridge token: <token>`
2. Reload browser extension after any `manifest.json` change.
3. Copy the current token from the Burp `ClientSideEye` tab into the popup and click `Save Bridge Token`.
4. Re-open popup and run scan again.
5. Check popup status for:
   - `Bridge: http://127.0.0.1:<port>`
   - `Sent: <n>`

### Find Hint or Reveal snippet syntax errors

If Console shows `SyntaxError` for hint snippets, update to the latest build. Current hints emit quote-safe selectors, for example:

```js
inspect(document.querySelector('[data-testid="localization-tab-save"]'))
```

### False positives from source maps/assets

ClientSideEye skips non-HTML payloads (e.g., `.js.map`, `.js`, `.css`, images/fonts) during HTML analysis.  
If old findings remain, click **Clear Findings** and run analysis again.

## Non-goals

ClientSideEye does not exploit vulnerabilities or bypass authorization.
It highlights client-side anti-patterns for manual validation.

## Change Tracking

See `CHANGELOG.md` for changes, improvements, and feature requests.

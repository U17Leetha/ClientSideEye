# ClientSideEye

ClientSideEye is a Playwright-based CLI for authorized web application security testing focused on identifying client-side control weaknesses, including:

Hidden or disabled UI controls used as access control

Password masking issues where secrets remain in the DOM

Role / permission hints embedded in client-side attributes

It produces:

A JSON report suitable for evidence and tooling

A human-readable terminal summary for fast triage

⚠️ Authorized testing only. Do not use against systems you do not own or explicitly have permission to assess.

## Install
Requirements

Node.js 18+

Playwright (Chromium)

## Clone & setup
```bash
git clone https://github.com/YOURNAME/ClientSideEye.git
cd ClientSideEye
npm install
npx playwright install chromium
```
## Make the CLI available

Option A – Local development (recommended)
```bash
npm link
```

Option B – Run directly
```bash
node src/clientsideeye.mjs --help
```
## CLI Options
```bash
clientsideeye <url> [options]
```
## Authentication
Use Playwright storage state (recommended for SSO / MFA flows)
```bash
--storage-state <auth.json>
```
Inject arbitrary HTTP headers
Examples:

Authorization: Bearer …

Cookie: ASP.NET_SessionId=…
```bash
--header "Name: value" (repeatable)
```
Inject cookies via Playwright’s cookie jar
```
--cookie "name=value" (repeatable)
```

## Modes

```bash
--mode report|soft-unhide|aggressive (default: report)
```
#### report
Detection only. No DOM modification.

#### soft-unhide
Reveals elements hidden via CSS, hidden, or aria-hidden.

#### aggressive
Also removes disabled, aria-disabled, and common disabled class tokens.

## Scope
```bash
--scope all|buttons (default: all)
```
#### all – Scan all common interactive elements

#### buttons – Focus on primary action controls

## Output
JSON report file path
```bash
--out <file.json> (default: client_controls_report.json)
```
Controls stdout format (JSON file is still written)
```
--output text|json (default: text)
```
Minimal terminal output
```
--quiet
```
Max findings printed to stdout
```
--max-items <n> (default: 20)
```
Include clipped outerHTML in terminal output
```
--show-html
```
Disable secret redaction in JSON (not recommended)
```
--no-redact
```

## DevTools / Inspection

Launch Chromium with DevTools open (requires HEADLESS=0)
```
--devtools
```
Scroll to and highlight the first matching finding
```
--focus password|hidden
```
Keep browser open after scan
```
--pause
```

## Timing / Safety

Delay after page load (useful for SPAs)
```
--wait-ms <ms> (default: 5000)
```
Cap number of DOM nodes inspected
```
--limit <n> (default: 250)
```

## Environment

Run with visible browser UI
```
HEADLESS=0
```

## Help / Version
```
-h, --help
```
```
-v, --version
```
## Uses / Examples
Basic scan (headless)
```
clientsideeye 'https://target/app/page'
```
Headed scan with DevTools and password focus
```
HEADLESS=0 clientsideeye 'https://target/app/page' \
  --devtools \
  --focus password \
  --pause
```

Authenticated scan using cookies
```
HEADLESS=0 clientsideeye 'https://target/app/page' \
  --header 'Cookie: .ASPXFORMSAUTH=XXX; ASP.NET_SessionId=YYY' \
  --focus hidden \
  --pause
```

Auth via Authorization header
```
clientsideeye 'https://target/app/page' \
  --header 'Authorization: Bearer YOUR_TOKEN'
```

Reveal hidden controls
```
HEADLESS=0 clientsideeye 'https://target/app/page' \
  --mode soft-unhide \
  --pause
```

Aggressive reveal (enable disabled controls)
```
HEADLESS=0 clientsideeye 'https://target/app/page' \
  --mode aggressive \
  --pause
```

JSON output to stdout
```
clientsideeye 'https://target/app/page' --output json
```

## Notes on Findings

Hidden UI ≠ vulnerability by itself
ClientSideEye highlights UI-based restrictions that should be validated with server-side authorization testing.

Password masking findings are high signal
Secrets present in the DOM or client-side state can often be extracted by low-privileged users.

Always confirm impact using server-side testing (e.g., Burp, manual requests).

## Responsible Use

ClientSideEye is intended for authorized security testing only.
You are responsible for ensuring you have permission to assess any target.

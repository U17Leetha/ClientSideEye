# ClientSideEye

ClientSideEye is a small Playwright-based CLI for **authorized** web app security testing that helps identify:
- **Client-side “filtering” / hidden UI controls** (buttons/links/inputs hidden or disabled in DOM/CSS)
- **Password masking issues** (masked fields with plaintext still present in `.value` or `value=""`)
- **Role/permission hints** in DOM attributes (e.g. `data-role`, `data-permission`, etc.)

It generates:
- A **JSON report** (default: `client_controls_report.json`)
- A **human-readable terminal summary** (default stdout)

> ⚠️ Authorized testing only. Do not use on systems you don’t own or have explicit permission to assess.

---

## Install

### Requirements
- Node.js 18+ (works great on 20+)
- Playwright + Chromium

### Clone & setup
```bash
git clone https://github.com/U17Leetha/ClientSideEye.git
cd ClientSideEye
npm install
npx playwright install chromium
npm link
'''

## Options

### Basic usage
clientsideeye <url> [options]

### Auth
Use Playwright storage state
    --storage-state <auth.json>
Add an HTTP header (ex: Authorization: bearer ..., Cookie: ...)
    --header 'Name: value' (use single qoutes)(repeatable)
Add a cookie into the Playwright cookie jar for the target domain
    --cookie 'Name=value' (repeatable)

### Modes
    --mode reports|soft-unhide|aggressive (default: report)
#### report
- Detect only, Does not modify the page
#### soft-unhide
- Attempts to reveal hidden elements (CSS/hidden/aria-hidden)
#### aggressive
- More invasive, removes disabled/aria-disabled and common "disabled" class tokens

### Scope
    --scope all|buttons (default: all)
#### all
- scans common interactive elements (buttons,a,input,etc)
#### buttons
- focuses on primary click targets (button,[role=button],links,etc)

### Output

    --out <file.json> (default: client_controls_report.json)

JSON report file path

    --output text|json (default: text)

Controls stdout format (JSON file is still written)

    --quiet

Minimal stdout (still writes JSON file)

    --max-items <n> (default: 20)

Limit how many findings are printed in terminal output

    --show-html

Include clipped outerHTML evidence in terminal output

    --no-redact

Write full auth values into the JSON report (NOT recommended)

### DevTools / inspection

    --devtools

Launch Chromium with DevTools open (headed only, use HEADLESS=0)

    --focus password|hidden

Scroll + outline the first matching finding for fast manual inspection

    --pause

Keep the browser open after the scan (so you can inspect/click around)

### Timing / safety

    --wait-ms <ms> (default: 5000)

Wait after initial page load (helpful for SPAs)

    --limit <n> (default: 250)

Cap number of nodes inspected (prevents runaway scans on huge pages)

### Environment

    HEADLESS=0

Run headed (show browser UI). Default behavior is headless.

### Help / version

    -h, --help

    -v, --version

## Uses / Examples
1) Basic scan (headless)
    clientsideeye 'https://target/app/page'

2) Headed run with DevTools + focus the first password issue
    HEADLESS=0 clientsideeye 'https://target/app/page' --devtools --focus password --pause

3) Auth via Cookie header (quote carefully)
    HEADLESS=0 clientsideeye 'https://target/app/page' \
      --header 'Cookie: .ASPXFORMSAUTH=XXX; ASP.NET_SessionId=YYY' \
      --devtools --focus hidden --pause

4) Auth via Authorization header
    clientsideeye 'https://target/app/page' \
      --header 'Authorization: Bearer YOUR_TOKEN_HERE'

5) Auth via Playwright storage state (best for SSO/MFA)

Create auth.json using Playwright (or export from an existing flow), then:

    clientsideeye 'https://target/app/page' --storage-state auth.json

6) Reveal hidden controls (soft)
    HEADLESS=0 clientsideeye 'https://target/app/page' --mode soft-unhide --pause

7) Reveal + enable controls (aggressive)
    HEADLESS=0 clientsideeye 'https://target/app/page' --mode aggressive --pause

8) Print JSON to stdout (still writes JSON file too)
    clientsideeye 'https://target/app/page' --output json

9) Increase wait time for SPAs
    clientsideeye 'https://target/app/page' --wait-ms 12000

## Notes on findings

Hidden/disabled controls are not automatically a vuln. The point is to quickly locate UI-driven restrictions that should be backed by server-side authorization.

Password masking issues are often high-signal: if secrets appear in DOM/JS, they can often be extracted by lower-privileged users.

Always validate with server-side requests (Burp, etc.) before concluding impact.

## Responsible use

ClientSideEye is intended for defensive security and authorized assessments only.
You are responsible for ensuring you have permission to test the target(s).

















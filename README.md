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
git clone https://github.com/YOURNAME/ClientSideEye.git
cd ClientSideEye
npm install
npx playwright install chromium

# Security Policy

ClientSideEye is a Burp Suite extension for passively identifying client-side security
anti-patterns. As a security tool, we take reports of vulnerabilities in the extension itself
seriously.

## Supported versions

Only the latest released version of ClientSideEye is supported with security fixes.

## Reporting a vulnerability

If you discover a security issue in ClientSideEye itself (as opposed to a finding the tool
reports about a *target* application), please report it privately rather than opening a public
GitHub issue:

1. Open a [GitHub Security Advisory](../../security/advisories/new) for this repository, or
2. If that isn't available, open a regular issue with minimal detail asking for a private
   contact channel, and we will follow up.

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (a minimal Burp project/test page is ideal).
- The ClientSideEye version and Burp Suite version/edition you tested with.

We aim to acknowledge reports within a reasonable timeframe and will credit reporters in the
`CHANGELOG.md` once a fix is released, unless you prefer to remain anonymous.

## Scope

In scope:

- Code execution, HTML/script injection, or unintended network activity triggered by analyzing
  attacker-controlled HTTP responses or Browser Bridge input.
- Local privilege/trust issues in the Browser Bridge (`127.0.0.1` listener).
- Dependency vulnerabilities in bundled libraries (currently: `org.jsoup:jsoup`).

Out of scope:

- Findings that ClientSideEye itself reports about a target application — those are intentional
  detection results, not vulnerabilities in the extension.
- Issues that require an attacker to already have arbitrary local code execution on the
  analyst's machine (the Browser Bridge's threat model explicitly assumes the local machine
  itself is trusted; see `README.md`'s "Security Model" section).

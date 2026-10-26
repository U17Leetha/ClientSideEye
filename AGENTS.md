# ClientSideEye maintenance

The authoritative upstream is https://github.com/U17Leetha/ClientSideEye. This local directory retains the historical ClientSideEye-Burp name; do not synchronize it from the old ClientSideEye-Burp repository.

Run `./gradlew check jar` with Java 17 and Node 24. The build refreshes `ClientSideEye-Burp.jar`; Montoya is supplied by Burp and must not be bundled. Security-sensitive behavior and explicit input budgets are documented in `DESIGN.md`.

The adjacent ClientSideEye-Lab is intentionally vulnerable and is a fixture, not a production hardening target.

# Release verification

Date: 2026-11-02. Environment: Linux, Python 3.12.14.

- Automated suite: **91 passed**. Includes Phase 1–4, system tests and new security/migration regressions.
- Exact release archive is extracted and the full suite rerun before delivery.
- Real local smoke: foreground agent submitted a sample over loopback HTTP to a temporary Flask/Werkzeug server; one telemetry row was verified in SQLite. No remote command or external notification was sent.
- Python compilation, JavaScript syntax and shell syntax checks passed.
- `requirements-tested.txt` records the installed validation environment.

## Limits

Browser rendering/click QA was not completed: Chromium download returned invalid archives. Native Windows/macOS installation, signing, live notification providers, hosted HTTPS deployment, large-fleet throughput and long-duration reliability remain unverified. Tests using OS mocks do not establish native-platform compatibility. No labelled attack-detection evaluation was performed.

This release fixes the reviewed defects; it is not a claim of production readiness or absence of all vulnerabilities. See docs/VERIFICATION_REPORT.md and docs/MIGRATION_CREDENTIALS.md.

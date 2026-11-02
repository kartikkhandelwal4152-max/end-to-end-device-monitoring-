# Verification report — corrected release

Date: 2026-11-02. Scope: local source changes, automated regressions and local agent/API smoke test. No live endpoints, credentials, cloud resources or external recipients were changed.

## Changes

- API access now uses login-issued user sessions only. Initial admin credentials are passwords, not master bearer tokens. Local recovery resets the admin password and revokes all sessions while preserving MFA. Enabling MFA revokes the enrolled user's sessions; successful TOTP login codes cannot be replayed within the same step.
- Database upgrades add columns before dependent indexes inside a transaction, preserve existing data and label old dispatched commands `legacy_unverified`.
- Kill requests require process name and finite creation time. Dashboard includes creation time/path, agent verifies identity/path, and critical processes remain blocked.
- Endpoint command acknowledgements are device-bound; terminal results cannot be changed. Duplicate telemetry retries still receive pending commands. Commands include expiry. A pre-action durable journal prevents automatic repeat of interrupted actions and explicitly reports unknown outcomes.
- User deletion removes dependent sessions transactionally. Failed authentication/authorization audit events survive error-response rollback. Login endpoint enforces rate limiting.
- Default-device startup is a no-op for existing devices. Container initialization does not print credentials into logs and requires a privately supplied initial password.
- Dashboard includes username/password/MFA login, self-enrollment, server logout, role-aware kill controls and authenticated report preview. Twilio sender/SID inputs and dedicated notification-test routes are wired.
- Arbitrary forwarding headers are no longer used as public-IP evidence. JSON arrays and invalid process identity types are rejected.
- Queue encryption claims are removed: storage is permission-protected plaintext. Setup uses local release files and JSON enrollment rather than downloading an unpinned agent or sourcing shell configuration.

## Verification

The complete extracted-release suite is run before delivery; the final count is recorded in TEST_REPORT.md. Coverage includes previous Phase 1–4/system tests plus regressions for password/session revocation, MFA bypass/replay, login throttling, old-schema upgrade, startup preservation of rotated tokens, session-bearing user deletion, required process identity and path validation, duplicate delivery/terminal ACK invariants, interrupted/corrupt journals, trusted proxies and input validation.

JavaScript syntax, Python compilation and shell syntax checks were run. A real foreground agent delivered one sample over loopback HTTP to a temporary Flask server and SQLite database. No kill command was executed and no real notification recipient was contacted.

## Not verified / remaining boundaries

- Full browser rendering and click interactions: Chromium download returned invalid archives. HTML/API/JavaScript contract checks pass, but visual browser QA is not claimed.
- Native Windows/macOS installation, OS permissions, keychain/DPAPI, signed executables, and long-duration reliability.
- Live Telegram/Twilio/Fast2SMS/WhatsApp delivery or hosted HTTPS deployment.
- Production throughput, multi-process workers, crash-proof exactly-once remote effects, labelled attack-detection accuracy and compliance.
- Retention is provided as a CLI operation; an operator must schedule it. Notification retries can duplicate provider delivery after an ambiguous network failure. The worker is intended for one backend process.

Read SECURITY_CLAIMS.md and MIGRATION_CREDENTIALS.md before a controlled pilot. No claim that every possible vulnerability has been eliminated is made.

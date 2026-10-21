# Verification report

Date: 8 October 2026

## Passed

- `python -m pytest -q`: **18 tests passed** on Linux with Python 3.12.
- Device/admin authentication separation and device-ID/token binding.
- Payload validation including non-finite numbers, invalid timestamps and malformed processes.
- Idempotent telemetry retries without double-counting failed logins.
- Five-minute failed-login window, CPU rule, duplicate-alert cooldown and authenticated acknowledgement.
- Telemetry and acknowledgement persistence after creating a new app instance.
- Explicit unavailable connection/login values rather than invented zero readings.
- Minimum ML baseline requirement; synthetic normal baseline followed by an outlier generates an ML alert and two rule alerts.
- OpenSSH log tailing: initial EOF, partial lines, ordinary rotation and truncation.
- Agent URL restrictions and real psutil collection.
- Separate live smoke check: foreground agent submitted a real sample to an ephemeral Waitress HTTP server on loopback; data was confirmed through the authenticated overview API backed by SQLite.
- `node --check static/app.js` and Python compilation passed.

## Not verified

- Full browser rendering and click interactions: a Chromium runtime was unavailable; attempted browser download returned invalid archives in this environment. No visual/browser QA is claimed.
- HTTPS reverse-proxy setup: example configuration supplied, not deployed.
- Windows/macOS operation, journal-only log sources, large fleets and long-duration reliability.
- Attack-detection precision/recall: no labelled attack evaluation was performed.

The demonstration proves that the implemented flow runs; it does not establish production readiness or real-world attack-detection accuracy.

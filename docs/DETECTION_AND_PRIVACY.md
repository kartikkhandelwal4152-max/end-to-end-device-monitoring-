# Detection and privacy

Process names, USB presence, and file-transfer domains are investigation indicators, not proof of malicious behaviour or exfiltration. Allowlisting reduces noise but requires review. Processes may be truncated by the configurable inventory limit; missing OS permissions reduce visibility. Remote destinations and full event-level network analysis are not a complete EDR sensor.

Browser-history and active-window collection are disabled by default. Domain-only collection removes paths/query strings. Do not enable full URLs or command-line capture without a documented need. Redaction patterns are best effort and may miss secrets; treat telemetry and backups as sensitive.

Isolation Forest flags unusual aggregate metric combinations, not attack probability. Training must use a representative trusted baseline. Time-aware deltas and model rollback exist, but labelled production evaluation and drift monitoring remain unverified. Synthetic tests do not measure real-world precision/recall. Offline backlog can still affect temporal analysis; investigate original observation times.

Self-reported script integrity is not attestation. No hardware-backed identity or tamper-proof audit ledger is implemented. The report is an operational summary, not compliance evidence.

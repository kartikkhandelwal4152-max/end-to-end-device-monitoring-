# Credential and local data protection

This build uses permissions-protected storage, not application-level encryption. Telemetry payloads are plain JSON inside SQLite. Command receipts are JSON. No AES-GCM, SQLCipher, DPAPI or Keychain integration is implemented. Use operating-system disk encryption where required; do not describe host identifiers as secret encryption keys.

The agent stores queues and receipts in `~/.sentinel/<server-origin-hash>/`, separating deployments. Directories use 0700 and files use 0600 on POSIX. Windows ACLs require platform verification. These controls do not protect against a compromised account or administrator.

Device secrets are supplied through `SENTINEL_DEVICE_TOKEN` or the hidden terminal prompt. The server stores SHA-256 digests. Passwords use salted PBKDF2; sessions are random expiring tokens stored as hashes. Browser sessions live in memory, never URL parameters or localStorage. MFA secrets and notification credentials are stored in the server database; protect the database and backups.

Never commit populated configuration, databases, queues, receipts, tokens or backup files. Rotate all tokens exposed in older ZIPs. Credential removal from source does not revoke them. See MIGRATION_CREDENTIALS.md.

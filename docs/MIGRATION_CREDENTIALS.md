# Upgrade and credential migration

Stop the old server and keep a backup of its complete data directory (`config.json`, SQLite database and associated WAL state). Prefer the old version's backup command or SQLite backup API. Test restore before replacing production data. Keep the previous source release for rollback.

From the new source:

```
python server.py --data-dir /path/to/data migrate
python server.py --data-dir /path/to/data rotate-admin
python server.py --data-dir /path/to/data serve
```

`rotate-admin` is local recovery. It prints a new password for username `admin`, invalidates the old password and revokes all sessions. It preserves existing MFA. Raw master/admin tokens no longer authenticate API requests. On a legacy database without users, recovery creates the admin account. Do not reuse an exposed old admin token as a password.

If MFA is lost, an authorized operator must perform an offline, audited recovery of that account; this build deliberately has no remote MFA bypass. Preserve your authenticator backup. Recovery of a lost factor is not implemented as a dashboard operation.

For each previously exposed device token:

```
python server.py --data-dir /path/to/data rotate DEVICE-ID
```

Replace its secret on that endpoint and restart its agent. Existing endpoints are not automatically updated. To block a device immediately, use `revoke DEVICE-ID`. Startup `ensure-device` never overwrites existing credentials, including rotated or revoked credentials.

Migrations add columns before indexes inside a transaction. Old `executed=1` commands become `legacy_unverified`, because the old server only proved dispatch, not execution. They are never replayed. Re-running migration is supported. Do not run the old source against the migrated DB; rollback means stopping the new server and restoring the pre-upgrade backup with the old source. Rollback loses events recorded after that backup, so preserve them separately first.

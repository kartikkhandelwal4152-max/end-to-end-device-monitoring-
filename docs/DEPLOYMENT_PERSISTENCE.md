# Deployment, backup and storage

Run a single backend process. The `serve` command starts the heartbeat monitor and notification worker; importing `create_app` in another WSGI launcher does not start workers automatically. Multiple worker processes are not supported by this release's in-process locks/rate limits.

`compose.yaml` mounts a named Docker volume at `/data`. The supplied Render configuration requests a persistent disk and a paid instance (`starter`); review costs and current plan support before deploying. No hosted resources have been created or changed. The Railway descriptor alone does not provision persistent storage: attach a volume at `/data` in that service before using it.

`/api/health` is liveness. `/api/ready` checks database integrity and required table access. Keep the API behind HTTPS; only set `SENTINEL_BEHIND_PROXY` and `SENTINEL_PROXY_HOPS` for your actual trusted proxy topology. Do not expose the origin directly if trusting proxy headers.

```
python server.py --data-dir /data backup --out /secure-backups/sentinel.db
python server.py --data-dir /data prune --days 30
```

Backups contain sensitive data. Copy `config.json` securely too. Retention pruning is a CLI operation, not an automatically scheduled task. Stop the server before restoring:

```
python server.py --data-dir /data restore /secure-backups/sentinel.db
```

Recovery, queue growth, disk space and long-duration concurrency should be tested on the target host. The notification worker has bounded batches/retries but no multi-process delivery coordination or exactly-once provider delivery guarantee. Alert floods and retention schedules need operational monitoring.

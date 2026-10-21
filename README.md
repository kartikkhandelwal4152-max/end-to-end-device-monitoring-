# Sentinel — End-to-End Device Monitoring & Cybersecurity

A runnable academic prototype: Python endpoint agent → authenticated Flask API → SQLite → rules + Isolation Forest → administrator dashboard.

## Start here: five-minute demo

Requires Python 3.11 or newer. Extract the ZIP, open a terminal in the `sentinel` folder, then:

```bash
python -m venv .venv
```

Activate your environment:

- Windows PowerShell: `.venv\Scripts\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`
- If `python` is unavailable on macOS/Linux, use `python3` to create the environment.
- If PowerShell activation is blocked, use `.venv\Scripts\python.exe` in place of `python`; no policy change is needed.

```bash
python -m pip install -r requirements.txt
python server.py init
```

**Save the administrator token shown once.** It is needed to unlock the dashboard. The server stores only its hash. There is no preset password.

```bash
python server.py demo
python server.py serve
```

Open **http://127.0.0.1:8000**, paste your administrator token, and click **Connect dashboard**.

The demo generates 80 synthetic baseline samples, trains a model, then submits one synthetic unusual sample. Expect three alerts: high CPU, five failed logins, and ML anomaly. Synthetic devices have a `DEMO-` prefix and an explicit simulated-data warning. Their samples are generated rapidly, so their timeline spans seconds. A demo device goes offline after 60 seconds because it is not a running agent. Repeating `demo` adds another simulated device.

## Monitor your own computer

Leave the server running. Open another terminal in this folder and activate the same virtual environment:

```bash
python server.py register LAPTOP-01
```

Save the separate device token, then run:

```bash
python agent.py --device LAPTOP-01 --server http://127.0.0.1:8000 --allow-local-http
```

Paste the **device** token at the hidden prompt. Do not use the administrator token. An alternative is the `SENTINEL_DEVICE_TOKEN` environment variable. The agent runs in the foreground, sends approximately every 10 seconds, and stops with Ctrl+C. This project does not install a service or monitor any computer automatically.

The dashboard refreshes every five seconds. It shows registered/online devices, CPU, RAM, connection counts, up to 100 process names and PIDs, models, and alerts. Processes, metrics and login counts are collected; file contents, passwords, keystrokes and packet contents are not collected.

### Linux OpenSSH failed logins

If your distribution writes OpenSSH failures to a readable text log:

```bash
python agent.py --device LAPTOP-01 --server http://127.0.0.1:8000 --allow-local-http --auth-log /var/log/auth.log
```

Some distributions use `/var/log/secure`; journal-only systems need a separate adapter, not provided here. Grant the agent only the permissions required to read your chosen log. The collector begins at the end of the log and reads new `sshd: Failed password/publickey` lines. It handles ordinary rename rotation and truncation, although unread lines in an old rotated file can be lost. It does not import historical failures and does not cover all login methods. Windows Event Log and macOS login adapters are not implemented.

**Rule:** five failure events across the device in a five-minute server-receipt window. This is not “five consecutive failures for one account.” Counting by server receipt is simple but delayed/offline batches may shift the window. A future version should transmit individual timestamped login events and account identifiers.

### Train on a baseline

Collect at least 30 complete samples during representative, trusted normal activity (about five minutes at the default interval), then run in another terminal:

```bash
python server.py train LAPTOP-01
```

For a useful baseline, prefer hours or days covering typical workloads. Thirty samples is only the prototype's minimum. Training uses the latest 1,000 records by default; `--limit 5000` changes that cap. Inspect the recent activity before training. A baseline containing attacks will weaken detection. Never mix synthetic demo records into a real device's baseline.

Models are separate per device. Features: CPU %, RAM %, process count, connection count, bytes/second, CPU change and connection-count change from the preceding sample. Differences are sample-to-sample, not time-normalized; use a consistent collection interval. This version has no sustained-trend or rolling-window ML features. The first training row uses zero deltas. Missing connection counts cause exclusion from training and skip ML scoring at ingestion; rules still run.

Isolation Forest uses 100 trees, `contamination=0.03`, and `random_state=42`. Negative decision-function scores are flagged as unusual; the score is not an attack probability. The contamination setting sets the training threshold, not measured detection accuracy. Models train explicitly, and incoming samples are scored against the existing baseline without automatic retraining. Numeric baseline records are stored in SQLite and used to reconstruct the model after restart; no untrusted pickle files are loaded.

## HTTPS for another device

The default server binds only to loopback. HTTP is allowed by the agent only for loopback when `--allow-local-http` is explicitly set. For another computer, use HTTPS and keep the backend behind a TLS reverse proxy.

`Caddyfile.example` gives an example for a domain you control. Replace `monitor.example.com`, point its DNS at your server, install Caddy, and configure firewall access for HTTPS. Keep port 8000 private and the backend bound to `127.0.0.1`. A publicly trusted certificate requires appropriate domain/ACME reachability; an internal network can instead use a trusted private CA.

```bash
caddy run --config Caddyfile.example --adapter caddyfile
```

On the endpoint:

```bash
python agent.py --device LAPTOP-01 --server https://monitor.example.com
```

For your private CA, add `--ca path/to/ca-bundle.pem`. Certificate verification is always enabled. Redirects are refused to avoid forwarding device credentials to another origin. Open the dashboard via the HTTPS origin too. TLS deployment depends on your own domain/network and has not been deployed or verified by this package.

## Project files

| File | Purpose |
|---|---|
| `server.py` | Initialization, registration, training, demo, Flask API, SQLite, alert rules |
| `agent.py` | Metrics, OpenSSH log tailing, verified HTTPS, bounded retry queue |
| `detection.py` | Feature engineering and Isolation Forest |
| `templates/index.html` | Administrator dashboard structure |
| `static/app.js` | Authenticated polling, charts and acknowledgement |
| `static/style.css` | Responsive dashboard styling |
| `tests/test_system.py` | Authentication, validation, rules, ML and agent tests |
| `requirements.txt` | Supported dependency ranges |
| `requirements-tested.txt` | Exact direct dependency versions used for verification |
| `TEST_REPORT.md` | Verification results and limits |

## API

| Method | Endpoint | Authentication |
|---|---|---|
| GET | `/api/health` | Public health only |
| POST | `/api/telemetry` | Device Bearer token + `X-Device-ID` |
| GET | `/api/overview` | Administrator Bearer token |
| GET | `/api/devices/<id>/history` | Administrator Bearer token |
| POST | `/api/alerts/<id>/ack` | Administrator Bearer token |

Telemetry requires `sample_id`, `observed` (Unix seconds), `cpu`, `ram`, `process_count`, `connections`, `bytes_per_second`, and `failed_logins`. Optional `processes` has up to 100 `{pid, name}` entries; optional `warnings` has up to 10 strings. `connections` and `failed_logins` may be null when unavailable. CPU/RAM are percentages; bytes/second is combined send+receive across interfaces. Payloads are capped at 64 KiB; timestamps must be within ten minutes of server time. Device/sample ID uniqueness makes retries idempotent within the accepted timestamp window. Older submissions are rejected. Server receipt order is used for ML deltas; clock accuracy still matters.

## Operations and limitations

- SQLite is the implemented relational database. MySQL support is not included.
- Rule alerts: CPU ≥95% (medium), five failed logins in five minutes (high). ML anomalies are medium severity. Same-device/same-kind alerts have a five-minute cooldown, including acknowledged alerts.
- Detection runs synchronously during ingestion, not as a background worker. This provides immediate results for a small demo, but CPU-bound model work and a process-local ingest lock limit scale. Run one backend process; move to a job queue and shared model service for a larger fleet.
- `data/` is generated locally and is excluded from this ZIP. SQLite contains potentially sensitive device/process data. Restrict filesystem access and plan retention/backups before a real deployment. No automatic deletion or encryption at rest is provided.
- Agent buffering is in-memory, at most 60 samples; oldest/over-nine-minute samples are dropped with a message. Buffered data is lost if the agent exits. There is no disk queue or guaranteed event delivery.
- Network visibility depends on platform and privileges; a successful psutil call may still provide a partial inventory. Unavailable counts appear explicitly. The collector sends connection **counts**, not remote addresses or a full connection inventory.
- CPU, RAM and process collection uses cross-platform psutil, but this package was tested on Linux only. Per-platform validation remains necessary.
- Chart.js and Bootstrap are loaded from pinned CDN URLs and require internet. If the chart library cannot load, current values, alerts and custom layout still work; the dashboard shows a chart warning. Self-host these assets for offline deployment.
- Device tokens can be rotated with `python server.py rotate LAPTOP-01`. Rotation invalidates the old token. There is no administrator token recovery command or multi-user login system yet; preserve the initial admin token securely.
- No automated blocking, malware removal, process termination, incident notification integration, account-based login correlation, rate limiting, or tamper-resistant agent is included.
- The model has not been evaluated on a labelled attack dataset. Demonstration anomaly detection is not evidence of real-world detection accuracy.

## Tests

```bash
python -m pytest -q
```

## Official technical references

- Isolation Forest: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- psutil metrics and permission behavior: https://psutil.readthedocs.io/stable/

## How to explain this project to faculty

“Humne ek endpoint agent banaya hai jo CPU, RAM, process aur available security signals collect karta hai. Har registered device ka alag authentication token hai. Backend verified data SQLite mein save karta hai. Rules known conditions detect karte hain aur Isolation Forest normal baseline se unusual metric combinations identify karta hai. Dashboard admin ko device status aur alerts dikhata hai. Abhi ye monitoring aur detection prototype hai; automatic attack blocking is version mein implement nahi hai.”
# icmp pings do -> for host ,zabbix
# Sentinel — endpoint monitoring prototype

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/kartikkhandelwal4152-max/end-to-end-device-monitoring-)

Python endpoint agent → Flask/Waitress → SQLite → rules + Isolation Forest → browser dashboard.

## Local start
Python 3.11+:

```bash
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python server.py init
python server.py serve
```

Initialization prints a random **password for username admin**. It is not an API token. Open http://127.0.0.1:8000 and sign in. For unattended initialization, supply `SENTINEL_ADMIN_PASSWORD` privately. Set up MFA from the dashboard; preserve the authenticator secret backup. Logout revokes the server session.

Optional synthetic demo: `python server.py demo`. Demo data is labelled and is not a real detection evaluation.

## Upgrade an older installation
**Back up first.** See `docs/MIGRATION_CREDENTIALS.md`. Run `migrate`, then local `rotate-admin` recovery before deploying this release over a legacy token-only installation. Raw admin bearer tokens are intentionally no longer accepted. Device tokens remain separate and keep working unless rotated/revoked. Rotate every token exposed in previous archives.

## Agent

```bash
python server.py register LAPTOP-01
python agent.py --device LAPTOP-01 --server http://127.0.0.1:8000 --allow-local-http
```

Paste the device token at the hidden prompt. Use HTTPS for remote endpoints. CA verification stays enabled. Agent buffering and command receipts persist under `~/.sentinel/<server-origin-hash>/`. Permission-protected files are not encrypted by this application.

Browser/window collection is opt-in. `python agent.py --help` lists controls. Train only after collecting a trusted normal baseline:

```bash
python server.py train LAPTOP-01
```

## Tests and evidence

```bash
python -m pytest -q
```

See `docs/VERIFICATION_REPORT.md` for actual checks and limits, `docs/SECURITY_CLAIMS.md` for security boundaries, and `docs/DEPLOYMENT_PERSISTENCE.md` for storage/backup instructions. The Render descriptor requests a paid persistent deployment; no hosting has been provisioned. Docker Compose supplies a local named volume. Railway still requires an attached persistent volume.

## Operational limits
This is a single-backend-process prototype. Tests do not prove real attack-detection accuracy, production capacity, OS-level installation, signed updates, or live SMS/Telegram delivery. Do not market it as certified EDR/DLP/compliance. Protect the data directory and backups; schedule retention explicitly.

Credentials, populated databases, queues and dependency folders are excluded from the deliverable. Review `docs/PILOT_FLEET_GUIDE.md` before a controlled pilot.


CREATE TABLE IF NOT EXISTS devices (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS telemetry (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 sample_id TEXT NOT NULL, received REAL NOT NULL, observed REAL NOT NULL,
 payload TEXT NOT NULL, score REAL, anomaly INTEGER NOT NULL DEFAULT 0,
 UNIQUE(device_id, sample_id));
CREATE INDEX IF NOT EXISTS telemetry_device_time ON telemetry(device_id, received);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 created REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
 message TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_device_kind ON alerts(device_id, kind, created);
CREATE TABLE IF NOT EXISTS models (
 device_id TEXT PRIMARY KEY REFERENCES devices(id), trained REAL NOT NULL,
 baseline TEXT NOT NULL, sample_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS commands (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES devices(id),
 action TEXT NOT NULL, payload TEXT NOT NULL, created REAL NOT NULL,
 executed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS commands_device_exec ON commands(device_id, executed);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY, value TEXT NOT NULL);

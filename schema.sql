-- Aegisly D1 (SQLite) schema
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_email TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  policy TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

-- Keys are stored only as SHA-256 hashes. role: 'admin' (dashboard) | 'member' (gateway)
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  label TEXT NOT NULL,
  role TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  monthly_budget_usd REAL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_keys_ws ON api_keys(workspace_id);

-- Tamper-evident audit log: each row hashes the previous row's hash.
-- Raw prompts are never stored, only their SHA-256.
CREATE TABLE IF NOT EXISTS audit_log (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL,
  key_id TEXT NOT NULL,
  model TEXT NOT NULL,
  decision TEXT NOT NULL,
  reasons TEXT NOT NULL,
  findings TEXT NOT NULL,
  prompt_hash TEXT NOT NULL,
  tokens INTEGER NOT NULL,
  cost_usd REAL NOT NULL,
  latency_ms INTEGER NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  PRIMARY KEY (workspace_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_audit_ws_ts ON audit_log(workspace_id, ts);

CREATE TABLE IF NOT EXISTS usage_monthly (
  workspace_id TEXT NOT NULL,
  month TEXT NOT NULL,
  key_id TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  redacted INTEGER NOT NULL DEFAULT 0,
  tokens INTEGER NOT NULL DEFAULT 0,
  cost_usd REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (workspace_id, month, key_id)
);

CREATE TABLE IF NOT EXISTS billing_events (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  type TEXT NOT NULL,
  from_plan TEXT,
  to_plan TEXT,
  amount_usd REAL NOT NULL DEFAULT 0,
  provider TEXT NOT NULL,
  reference TEXT
);

-- Policy snapshots table for Conditional Access baseline & drift diff
CREATE TABLE IF NOT EXISTS policy_snapshots (
  id TEXT PRIMARY KEY NOT NULL,
  snapshot_type TEXT NOT NULL,
  label TEXT NOT NULL,
  actor_upn TEXT NOT NULL,
  policy_count INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_snapshots_type_created
  ON policy_snapshots (snapshot_type, created_at);

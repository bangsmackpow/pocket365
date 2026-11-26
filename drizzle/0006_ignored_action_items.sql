CREATE TABLE IF NOT EXISTS ignored_action_items (
  id TEXT PRIMARY KEY NOT NULL,
  organization_id TEXT NOT NULL DEFAULT 'default',
  action_item_id TEXT NOT NULL,
  reason TEXT,
  ignored_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ignored_action_items_org
  ON ignored_action_items (organization_id, action_item_id);

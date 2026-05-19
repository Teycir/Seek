CREATE TABLE IF NOT EXISTS searches (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  query       TEXT NOT NULL,
  query_type  TEXT NOT NULL CHECK (query_type IN ('ip','domain','asn')),
  result_json TEXT NOT NULL,
  duration_ms INTEGER,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_searches_query
  ON searches (query, created_at DESC);

CREATE TABLE IF NOT EXISTS saved_targets (
  id          TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
  query       TEXT NOT NULL UNIQUE,
  label       TEXT,
  notes       TEXT,
  result_json TEXT,                            -- snapshot of last cron lookup
  checked_at  INTEGER,                         -- unix seconds — when cron last ran
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_saved_targets_created
  ON saved_targets (created_at DESC);

CREATE TABLE IF NOT EXISTS cache (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  expires_at INTEGER NOT NULL          -- unix seconds
);

CREATE INDEX IF NOT EXISTS idx_cache_expires
  ON cache (expires_at);

-- Migration for existing deployments that have the old schema without result_json / checked_at.
-- These are no-ops if the columns already exist (SQLite ignores ADD COLUMN on existing cols
-- only when using the IF NOT EXISTS pattern via a separate migration runner; the lines below
-- are included here as documentation — run them manually against existing D1 databases).
-- ALTER TABLE saved_targets ADD COLUMN result_json TEXT;
-- ALTER TABLE saved_targets ADD COLUMN checked_at  INTEGER;

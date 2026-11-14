// Control database. Shared tables (spaces, versions, manifest_files, users, sessions, activity_log,
// grants, api_keys) keep homefast's column names and types; freespace-only data lives in NEW
// columns/tables so a later homefast import is an ordinary migration (issue #214 section 8).
import { DatabaseSync } from 'node:sqlite';

const MIGRATIONS = [
  `
  CREATE TABLE spaces (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    team_id TEXT,
    owner_id TEXT,
    live_version_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    noindex INTEGER NOT NULL DEFAULT 1,
    archived_at TEXT,
    -- freespace-only:
    privacy TEXT NOT NULL DEFAULT 'team',   -- team | link | public  (link lands in M3)
    plugins_json TEXT NOT NULL DEFAULT '[]'
  );
  CREATE TABLE versions (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    number INTEGER NOT NULL,
    status TEXT NOT NULL,
    config_json TEXT,
    routing_json TEXT,
    total_files INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    finalized_at TEXT,
    -- freespace-only (history, section 5):
    parent_version_id TEXT,
    author_credential_id TEXT,
    author_name TEXT,
    message TEXT,
    source TEXT,                             -- mcp | ui | api | git-sync
    warnings_json TEXT,
    UNIQUE(space_id, number)
  );
  CREATE TABLE manifest_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    declared_size INTEGER,
    content_type TEXT NOT NULL,
    UNIQUE(version_id, path)
  );
  CREATE INDEX idx_manifest_version ON manifest_files(version_id);
  CREATE INDEX idx_manifest_sha256 ON manifest_files(sha256);

  CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,   -- the account email
    password_hash TEXT NOT NULL,                    -- PHC string ($scrypt$...)
    role TEXT NOT NULL DEFAULT 'member',            -- admin | member
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT,
    disabled_at TEXT,
    display_name TEXT                               -- freespace-only
  );
  CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    user_agent TEXT,
    ip TEXT
  );
  CREATE INDEX idx_sessions_user ON sessions(user_id);
  CREATE INDEX idx_sessions_expires ON sessions(expires_at);

  CREATE TABLE activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    space_id TEXT REFERENCES spaces(id) ON DELETE CASCADE,
    actor_kind TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    detail_json TEXT,
    created_at TEXT NOT NULL
  );
  CREATE INDEX idx_activity_log_space_created ON activity_log(space_id, created_at);

  -- Agent tokens / OAuth grants (M2). homefast api_keys columns, plus freespace-only scope columns.
  CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    last_used_at TEXT,
    kind TEXT NOT NULL DEFAULT 'agent_token',       -- agent_token | oauth
    scope_json TEXT NOT NULL DEFAULT '{}',
    client_name TEXT,
    client_id TEXT,
    revoked_at TEXT
  );
  CREATE INDEX idx_api_keys_prefix ON api_keys(token_prefix);

  -- Share links / passwords (M3). Same shape as homefast grants.
  CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    secret_hash TEXT,
    raw_token TEXT,
    paths_json TEXT NOT NULL DEFAULT '["/**"]',
    exclude_paths_json TEXT DEFAULT '[]',
    role TEXT NOT NULL DEFAULT 'viewer',
    target TEXT NOT NULL DEFAULT 'live',
    not_before TEXT,
    expires_at TEXT,
    max_uses INTEGER,
    uses_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    landing_path TEXT,
    revision INTEGER NOT NULL DEFAULT 1,
    last_used_at TEXT,
    rotated_at TEXT,
    updated_at TEXT,
    token_hint TEXT,
    -- freespace-only (per-link view tracking):
    disabled_at TEXT,
    first_viewed_at TEXT,
    view_count INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX idx_grants_space ON grants(space_id);

  -- freespace-only
  CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'member',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
  );
  CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
  `,
];

export function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  const { user_version: v } = db.prepare('PRAGMA user_version').get();
  for (let i = v; i < MIGRATIONS.length; i++) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[i]);
      db.exec(`PRAGMA user_version = ${i + 1}`);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }
  return db;
}

export function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

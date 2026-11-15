// Control database. Shared tables (spaces, versions, manifest_files, users, sessions, activity_log,
// grants, api_keys) keep Spacefast's column names and types; greenroom-only data lives in NEW
// columns/tables so a later Spacefast import is an ordinary migration.
import { DatabaseSync } from 'node:sqlite';
import { sha256hex } from './util.js';

export const MIGRATIONS = [
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
    -- greenroom-only:
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
    -- greenroom-only (history):
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
    display_name TEXT                               -- greenroom-only
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

  -- Agent tokens / OAuth grants (M2). Spacefast api_keys columns, plus greenroom-only scope columns.
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

  -- Share links / passwords (M3). Same shape as Spacefast grants.
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
    -- greenroom-only (per-link view tracking):
    disabled_at TEXT,
    first_viewed_at TEXT,
    view_count INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX idx_grants_space ON grants(space_id);

  -- greenroom-only
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
  // M2 (greenroom-only): OAuth. The grant itself is an api_keys row (kind 'oauth'); these hang off it,
  // so revoking or deleting the grant kills every token issued under it.
  `
  CREATE TABLE oauth_tokens (
    token_hash TEXT PRIMARY KEY,                    -- sha256 of the opaque token
    grant_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                             -- access | refresh
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT                                    -- refresh only: set on rotation; reuse revokes the grant
  );
  CREATE INDEX idx_oauth_tokens_grant ON oauth_tokens(grant_id);
  CREATE TABLE oauth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_name TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    grant_id TEXT
  );
  CREATE TABLE oauth_clients (                      -- dynamic registration (off unless an admin enables it)
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris_json TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  `,
  // M3: share links. The key lookup is one indexed read per request; last_viewed_at is
  // greenroom-only view tracking next to first_viewed_at and view_count.
  `
  ALTER TABLE grants ADD COLUMN last_viewed_at TEXT;
  CREATE INDEX idx_grants_token ON grants(raw_token);
  `,
  // Share keys are stored as sha256 (like api_keys and oauth_tokens), so the URL is shown once at
  // creation. raw_token stays in the schema for Spacefast compatibility but is left NULL.
  (db) => {
    db.exec('ALTER TABLE grants ADD COLUMN token_hash TEXT; CREATE UNIQUE INDEX idx_grants_token_hash ON grants(token_hash);');
    const set = db.prepare('UPDATE grants SET token_hash = ?, raw_token = NULL WHERE id = ?');
    for (const g of db.prepare('SELECT id, raw_token FROM grants WHERE raw_token IS NOT NULL').all()) set.run(sha256hex(g.raw_token), g.id);
  },
  // Plugin settings per space (core-owned; plugins reach them only through ctx.settings).
  `CREATE TABLE plugin_space (
    space_id TEXT NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    plugin TEXT NOT NULL,
    settings_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (space_id, plugin)
  );`,
  // M6 (greenroom-only): people. Single-use emailed links (signup, re-confirmation), stored as sha256.
  `
  ALTER TABLE users ADD COLUMN email_confirmed_at TEXT;
  CREATE TABLE email_tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                             -- signup | reconfirm
    email TEXT NOT NULL,
    user_id TEXT,                                   -- reconfirm only
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
  );
  CREATE INDEX idx_email_tokens_user ON email_tokens(user_id);
  `,
];

export function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  const { user_version: v } = db.prepare('PRAGMA user_version').get();
  for (let i = v; i < MIGRATIONS.length; i++) {
    db.exec('BEGIN');
    try {
      if (typeof MIGRATIONS[i] === 'function') MIGRATIONS[i](db); else db.exec(MIGRATIONS[i]);
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

// Accounts, sessions, and the credential layer: every auth method resolves to ONE credential object
// before any route runs; enforcement reads only that object (issue #214 section 6).
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { newId, now, randomToken, sha256hex, hmac, safeEqual } from './util.js';

const scrypt = promisify(crypto.scrypt);
const N = 2 ** 15, R = 8, P = 1;
export const SESSION_COOKIE = '__Host-fs_session';
// Used to burn equal time when the email is unknown.
const DUMMY = '$scrypt$ln=15,r=8,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export function httpErr(status, message) {
  return Object.assign(new Error(message), { status });
}

/** PHC string: $scrypt$ln=15,r=8,p=1$<salt b64>$<hash b64>, unpadded B64 per the PHC spec (section 8.4).
 *  Buffer.from(_, 'base64') reads padded and unpadded alike, so older padded hashes still verify. */
const b64 = (b) => b.toString('base64').replace(/=+$/, '');
export async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 32, { N, r: R, p: P, maxmem: 128 * N * R * 2 });
  return `$scrypt$ln=15,r=${R},p=${P}$${b64(salt)}$${b64(h)}`;
}
export async function verifyPassword(pw, phc) {
  const m = /^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/.exec(phc || '');
  if (!m) return false;
  const [n, r, p] = [2 ** +m[1], +m[2], +m[3]];
  const want = Buffer.from(m[5], 'base64');
  const got = await scrypt(pw, Buffer.from(m[4], 'base64'), want.length, { N: n, r, p, maxmem: 128 * n * r * 2 });
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

export const ALL_PERMS = ['publish', 'db', 'share', 'export', 'read'];
export const fullScope = () => ({ spaces: '*', create: true, perms: [...ALL_PERMS], readOnly: false });

export function parseCookies(h) {
  const out = {};
  for (const part of (h || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/** Structured scope; anything unrecognised makes the whole credential unusable (fail closed). */
export function normaliseScope(s) {
  if (!s || typeof s !== 'object') return null;
  const spaces = s.spaces === '*' ? '*' : Array.isArray(s.spaces) && s.spaces.every((x) => typeof x === 'string') ? s.spaces : null;
  if (!spaces || !Array.isArray(s.perms) || !s.perms.every((p) => ALL_PERMS.includes(p))) return null;
  return { spaces, create: s.create === true, perms: s.perms, readOnly: s.readOnly === true };
}

/**
 * OAuth scope strings <-> structured scope. space:{slug}, spaces:create, publish, db, share, export, read.
 * Anything else throws: an unknown string fails the whole request, never silently widens or narrows it.
 */
export function parseScopeString(str) {
  const sc = { spaces: [], create: false, perms: [], readOnly: false };
  for (const t of String(str || '').split(' ').filter(Boolean)) {
    if (t.startsWith('space:') && /^[a-z0-9-]+$/.test(t.slice(6))) sc.spaces.push(t.slice(6));
    else if (t === 'spaces:create') sc.create = true;
    else if (ALL_PERMS.includes(t)) sc.perms.push(t);
    else throw httpErr(400, `Unknown scope: ${t}`);
  }
  return sc;
}
export function scopeString(sc) {
  const sp = sc.spaces === '*' ? ['space:*'] : sc.spaces.map((s) => `space:${s}`);
  return [...sp, ...(sc.create ? ['spaces:create'] : []), ...sc.perms].join(' ');
}

/** Can this credential do `perm` on `slug`? (slug null => instance-level, e.g. listing.) */
export function can(cred, perm, slug = null) {
  if (!cred) return false;
  const sc = cred.scope;
  if (perm === 'create') return sc.create && !sc.readOnly;
  if (slug && sc.spaces !== '*' && !sc.spaces.includes(slug)) return false;
  if (!sc.perms.includes(perm)) return false;
  if (sc.readOnly && perm !== 'read') return false;
  return true;
}

/**
 * Escalation is closed as a set: user management, invites, tokens, instance settings and making a
 * space Public need a member's own session, never a scoped credential.
 */
export function requireSession(cred) {
  if (!cred || cred.type !== 'session') throw httpErr(403, 'This action needs a signed-in person');
}
export function requireAdmin(cred) {
  requireSession(cred);
  if (cred.user.role !== 'admin') throw httpErr(403, 'Admins only');
}

export function authorName(cred) {
  const who = cred.user.display_name || cred.user.username;
  return cred.type === 'session' ? who : `${cred.label || 'Agent'} (via ${who})`;
}
export const authorId = (cred) => (cred.type === 'session' ? cred.userId : cred.id);

export class Auth {
  constructor(db, config) {
    this.db = db;
    this.config = config;
  }

  userCount() { return this.db.prepare('SELECT COUNT(*) c FROM users').get().c; }
  getUser(id) { return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id); }
  activeUser(id) {
    const u = this.getUser(id);
    return u && !u.disabled_at ? u : null;
  }

  async createUser({ email, password, role = 'member', name }) {
    email = String(email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw httpErr(400, 'A valid email is required');
    if (String(password || '').length < 10) throw httpErr(400, 'Password must be at least 10 characters');
    if (this.db.prepare('SELECT 1 FROM users WHERE username = ?').get(email)) throw httpErr(409, 'Email already registered');
    const id = newId('usr'), t = now();
    this.db.prepare(
      'INSERT INTO users (id, username, password_hash, role, created_at, updated_at, display_name) VALUES (?,?,?,?,?,?,?)',
    ).run(id, email, await hashPassword(password), role, t, t, name || email.split('@')[0]);
    return this.getUser(id);
  }

  async login(email, password, meta = {}) {
    const u = this.db.prepare('SELECT * FROM users WHERE username = ?').get(String(email || '').trim());
    const ok = await verifyPassword(String(password || ''), u ? u.password_hash : DUMMY);
    if (!u || !ok || u.disabled_at) throw httpErr(401, 'Invalid email or password');
    return this.createSession(u.id, meta);
  }

  createSession(userId, { userAgent, ip } = {}) {
    const id = newId('ses', 24), t = now();
    const expires = new Date(Date.now() + this.config.sessionDays * 864e5).toISOString();
    this.db.prepare(
      'INSERT INTO sessions (id,user_id,csrf_token,created_at,last_seen_at,expires_at,user_agent,ip) VALUES (?,?,?,?,?,?,?,?)',
    ).run(id, userId, randomToken(24), t, t, expires, userAgent ?? null, ip ?? null);
    this.db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(t, userId);
    return { id, cookie: `${id}.${hmac(this.config.secret, `session:${id}`)}`, expires };
  }
  /** The active user behind a live (unrevoked, unexpired) session id, else null. */
  sessionUser(id) {
    const s = this.db.prepare('SELECT user_id FROM sessions WHERE id = ? AND revoked_at IS NULL AND expires_at > ?').get(String(id), now());
    return s ? this.activeUser(s.user_id) : null;
  }
  revokeSession(id) { this.db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(now(), id); }

  sessionFromCookie(value) {
    const i = (value || '').lastIndexOf('.');
    if (i < 1) return null;
    const id = value.slice(0, i);
    if (!safeEqual(value.slice(i + 1), hmac(this.config.secret, `session:${id}`))) return null;
    const s = this.db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
    if (!s || s.revoked_at || s.expires_at < now()) return null;
    return s;
  }

  /**
   * The one place a request becomes a credential; null when unauthenticated.
   * { type, id, userId, user, scope, grantedBy, expiresAt, via }
   */
  resolve(req) {
    const authz = req.headers.authorization || '';
    if (authz.startsWith('Bearer ')) return this.#token(authz.slice(7).trim());
    const s = this.sessionFromCookie(parseCookies(req.headers.cookie)[SESSION_COOKIE]);
    if (!s) return null;
    const u = this.activeUser(s.user_id); // live constraint: disabled user => dead session
    if (!u) return null;
    return {
      type: 'session', id: s.id, userId: u.id, user: u, scope: fullScope(),
      grantedBy: u.id, expiresAt: s.expires_at, csrf: s.csrf_token, via: 'cookie',
    };
  }

  #token(token) {
    let row;
    if (token.startsWith('fsa_') && token.length >= 16) {
      row = this.db.prepare("SELECT * FROM api_keys WHERE token_prefix = ? AND kind = 'agent_token' AND revoked_at IS NULL").get(token.slice(0, 12));
      if (row && !safeEqual(row.key_hash, sha256hex(token))) row = null;
    } else if (token.startsWith('fso_')) {
      // OAuth access token: opaque, stored hashed, one indexed lookup; the grant row carries the scope.
      row = this.db.prepare(
        "SELECT k.* FROM oauth_tokens t JOIN api_keys k ON k.id = t.grant_id WHERE t.token_hash = ? AND t.kind = 'access' AND t.expires_at > ? AND k.revoked_at IS NULL",
      ).get(sha256hex(token), now());
    }
    return row ? this.#fromRow(row, true) : null;
  }

  /** The live credential behind an api_keys row id (signed export links), else null. Same live checks as a request. */
  keyCred(id) {
    const row = this.db.prepare("SELECT * FROM api_keys WHERE id = ? AND revoked_at IS NULL AND kind IN ('agent_token','oauth')").get(String(id));
    return row ? this.#fromRow(row, false) : null;
  }

  #fromRow(row, touch) {
    if (row.expires_at && row.expires_at < now()) return null;
    const granter = this.activeUser(row.user_id); // live constraint: removed member => credential dies
    if (!granter) return null;
    let scope = null;
    try { scope = normaliseScope(JSON.parse(row.scope_json)); } catch { /* fail closed */ }
    if (!scope) return null;
    if (touch) this.db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now(), row.id);
    return {
      type: row.kind === 'oauth' ? 'oauth' : 'agent_token', id: row.id, userId: granter.id, user: granter,
      scope, grantedBy: granter.id, expiresAt: row.expires_at, label: row.client_name || row.name, via: 'bearer',
    };
  }

  /** Revoking a grant or pasted token kills it and every access/refresh token issued under it. */
  revokeKey(id) {
    this.db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(now(), id);
    this.db.prepare('DELETE FROM oauth_tokens WHERE grant_id = ?').run(id);
  }
}

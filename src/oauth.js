// OAuth 2.1 authorization server for MCP clients (issue #214 section 6).
// Public clients only: auth code + PKCE (S256), client_id is a Client ID Metadata Document URL
// (dynamic registration is off unless an admin turns it on). The approved grant IS an api_keys row
// (kind 'oauth'), so it sits in the same list and revokes the same way as a pasted token.
import crypto from 'node:crypto';
import { httpErr, parseScopeString, scopeString, normaliseScope, requireSession } from './auth.js';
import { fetchJson } from './ssrf.js';
import { newId, now, randomToken, sha256hex, safeEqual } from './util.js';

const ACCESS_TTL = 3600e3, REFRESH_TTL = 30 * 864e5, CODE_TTL = 120e3;
export const SCOPES_SUPPORTED = ['spaces:create', 'publish', 'db', 'share', 'export', 'read'];
const later = (ms) => new Date(Date.now() + ms).toISOString();

/** OAuth error body: RFC 6749 shape. */
export const oauthErr = (status, error, description) => Object.assign(httpErr(status, description || error), { oauth: error });

export class OAuth {
  constructor({ db, auth, config }) {
    this.db = db;
    this.auth = auth;
    this.config = config;
    this.fetchMetadata = config.fetchClientMetadata || fetchJson; // injectable for tests
  }

  issuer(req) { return (this.config.publicUrl || `https://${req.headers.host}`).replace(/\/$/, ''); }
  dcrEnabled() { return this.db.prepare("SELECT value FROM meta WHERE key = 'dcr_enabled'").get()?.value === '1'; }
  setDcr(on) { this.db.prepare("INSERT INTO meta (key, value) VALUES ('dcr_enabled', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(on ? '1' : '0'); }

  protectedResource(req) {
    const iss = this.issuer(req);
    return { resource: `${iss}/mcp`, authorization_servers: [iss], scopes_supported: SCOPES_SUPPORTED, bearer_methods_supported: ['header'] };
  }
  serverMetadata(req) {
    const iss = this.issuer(req);
    return {
      issuer: iss,
      authorization_endpoint: `${iss}/oauth/authorize`,
      token_endpoint: `${iss}/oauth/token`,
      revocation_endpoint: `${iss}/oauth/revoke`,
      ...(this.dcrEnabled() && { registration_endpoint: `${iss}/oauth/register` }),
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      client_id_metadata_document_supported: true,
      scopes_supported: SCOPES_SUPPORTED,
    };
  }

  /** client_id -> { client_id, client_name, redirect_uris }. CIMD URLs are fetched through the SSRF guard. */
  async client(clientId) {
    clientId = String(clientId || '');
    if (clientId.startsWith('dcr_')) {
      const row = this.dcrEnabled() && this.db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(clientId);
      if (!row) throw httpErr(400, 'Unknown client');
      return { client_id: row.client_id, client_name: row.client_name, redirect_uris: JSON.parse(row.redirect_uris_json) };
    }
    let u;
    try { u = new URL(clientId); } catch { throw httpErr(400, 'client_id must be an https URL'); }
    if (u.protocol !== 'https:' || u.pathname === '/' || u.hash || u.username || u.password) throw httpErr(400, 'client_id must be an https URL with a path');
    let doc;
    try { doc = await this.fetchMetadata(clientId); } catch (e) { throw httpErr(400, `Could not load client metadata: ${e.message}`); }
    if (!doc || doc.client_id !== clientId) throw httpErr(400, 'Client metadata client_id does not match its URL');
    if (!Array.isArray(doc.redirect_uris) || !doc.redirect_uris.every((r) => typeof r === 'string')) throw httpErr(400, 'Client metadata has no redirect_uris');
    const name = typeof doc.client_name === 'string' && doc.client_name.trim() ? doc.client_name.trim().slice(0, 80) : u.host;
    return { client_id: clientId, client_name: name, redirect_uris: doc.redirect_uris };
  }

  /**
   * Validates an authorization request. Client and redirect_uri problems throw (shown, never redirected);
   * anything after that returns { error } to send back to the client's redirect_uri.
   */
  async checkRequest(p) {
    const client = await this.client(p.client_id);
    if (!client.redirect_uris.includes(p.redirect_uri)) throw httpErr(400, 'redirect_uri is not registered for this client');
    const back = { client, redirect_uri: p.redirect_uri, state: p.state };
    if (p.response_type !== 'code') return { ...back, error: 'unsupported_response_type' };
    if (p.code_challenge_method !== 'S256' || !/^[\w-]{43,128}$/.test(p.code_challenge || '')) return { ...back, error: 'invalid_request', desc: 'PKCE with S256 is required' };
    try { back.requested = parseScopeString(p.scope); } catch (e) { return { ...back, error: 'invalid_scope', desc: e.message }; }
    return back;
  }

  redirectWith(redirectUri, params, req) {
    const u = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) u.searchParams.set(k, v);
    u.searchParams.set('iss', this.issuer(req));
    return u.toString();
  }

  /** The person's consent form came back: mint a single-use code bound to client, redirect and PKCE challenge. */
  async approve(cred, p, req) {
    requireSession(cred); // approving a grant is escalation: never from a scoped credential
    const r = await this.checkRequest(p);
    if (r.error) return this.redirectWith(r.redirect_uri, { error: r.error, error_description: r.desc, state: r.state }, req);
    if (p.decision !== 'approve') return this.redirectWith(r.redirect_uri, { error: 'access_denied', state: r.state }, req);
    const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
    const known = new Set(this.db.prepare('SELECT slug FROM spaces WHERE archived_at IS NULL').all().map((s) => s.slug));
    const scope = normaliseScope({
      spaces: list(p.spaces).filter((s) => known.has(s)),
      create: p.create === '1',
      perms: list(p.perms),
    });
    if (!scope) return this.redirectWith(r.redirect_uri, { error: 'invalid_scope', state: r.state }, req);
    const code = randomToken(32);
    this.db.prepare('INSERT INTO oauth_codes (code_hash,client_id,client_name,redirect_uri,code_challenge,user_id,scope_json,expires_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(sha256hex(code), r.client.client_id, r.client.client_name, r.redirect_uri, p.code_challenge, cred.userId, JSON.stringify(scope), later(CODE_TTL));
    return this.redirectWith(r.redirect_uri, { code, state: r.state }, req);
  }

  #issue(grantId) {
    const access = 'gro_' + randomToken(32), refresh = 'grr_' + randomToken(32), t = now();
    const ins = this.db.prepare('INSERT INTO oauth_tokens (token_hash,grant_id,kind,created_at,expires_at) VALUES (?,?,?,?,?)');
    ins.run(sha256hex(access), grantId, 'access', t, later(ACCESS_TTL));
    ins.run(sha256hex(refresh), grantId, 'refresh', t, later(REFRESH_TTL));
    const g = this.db.prepare('SELECT scope_json FROM api_keys WHERE id = ?').get(grantId);
    return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL / 1000, refresh_token: refresh, scope: scopeString(JSON.parse(g.scope_json)) };
  }

  token(p) {
    if (p.scope !== undefined) {
      try { parseScopeString(p.scope); } catch (e) { throw oauthErr(400, 'invalid_scope', e.message); }
    }
    if (p.grant_type === 'authorization_code') {
      const row = this.db.prepare('SELECT * FROM oauth_codes WHERE code_hash = ?').get(sha256hex(String(p.code || '')));
      if (!row) throw oauthErr(400, 'invalid_grant', 'Unknown code');
      if (row.used_at) { // replayed code: kill whatever it produced
        if (row.grant_id) this.auth.revokeKey(row.grant_id);
        throw oauthErr(400, 'invalid_grant', 'Code already used');
      }
      if (row.expires_at < now()) throw oauthErr(400, 'invalid_grant', 'Code expired');
      if (row.client_id !== p.client_id || row.redirect_uri !== p.redirect_uri) throw oauthErr(400, 'invalid_grant', 'client_id or redirect_uri mismatch');
      const verifier = String(p.code_verifier || '');
      if (!/^[\w.~-]{43,128}$/.test(verifier) || !safeEqual(crypto.createHash('sha256').update(verifier).digest('base64url'), row.code_challenge)) {
        throw oauthErr(400, 'invalid_grant', 'PKCE verification failed');
      }
      // Spend the code only once the caller has proved it is the client: someone holding a stolen code
      // but not the verifier can't burn it for the real client.
      this.db.prepare('UPDATE oauth_codes SET used_at = ? WHERE code_hash = ?').run(now(), row.code_hash);
      if (!this.auth.activeUser(row.user_id)) throw oauthErr(400, 'invalid_grant', 'The approving member is no longer active');
      // One grant per member+client: a step-up approval replaces the scope of the existing grant.
      const existing = this.db.prepare("SELECT id FROM api_keys WHERE kind = 'oauth' AND user_id = ? AND client_id = ? AND revoked_at IS NULL").get(row.user_id, row.client_id);
      const grantId = existing?.id || newId('key');
      if (existing) this.db.prepare('UPDATE api_keys SET scope_json = ?, client_name = ? WHERE id = ?').run(row.scope_json, row.client_name, grantId);
      else this.db.prepare("INSERT INTO api_keys (id,name,key_hash,token_prefix,user_id,created_at,kind,scope_json,client_name,client_id) VALUES (?,?,'','',?,?,'oauth',?,?,?)")
        .run(grantId, row.client_name, row.user_id, now(), row.scope_json, row.client_name, row.client_id);
      this.db.prepare('UPDATE oauth_codes SET grant_id = ? WHERE code_hash = ?').run(grantId, row.code_hash);
      return this.#issue(grantId);
    }
    if (p.grant_type === 'refresh_token') {
      const row = this.db.prepare(
        "SELECT t.*, k.client_id, k.user_id, k.revoked_at FROM oauth_tokens t JOIN api_keys k ON k.id = t.grant_id WHERE t.token_hash = ? AND t.kind = 'refresh'",
      ).get(sha256hex(String(p.refresh_token || '')));
      if (!row || row.revoked_at) throw oauthErr(400, 'invalid_grant', 'Unknown refresh token');
      if (row.used_at) { // rotation means a used refresh token is only ever presented by a thief (or a replay)
        this.auth.revokeKey(row.grant_id);
        throw oauthErr(400, 'invalid_grant', 'Refresh token reused; the grant has been revoked');
      }
      if (row.expires_at < now() || row.client_id !== p.client_id) throw oauthErr(400, 'invalid_grant', 'Refresh token expired or not for this client');
      if (!this.auth.activeUser(row.user_id)) throw oauthErr(400, 'invalid_grant', 'The approving member is no longer active');
      this.db.prepare('UPDATE oauth_tokens SET used_at = ? WHERE token_hash = ?').run(now(), row.token_hash);
      this.db.prepare("DELETE FROM oauth_tokens WHERE grant_id = ? AND kind = 'access'").run(row.grant_id);
      return this.#issue(row.grant_id);
    }
    throw oauthErr(400, 'unsupported_grant_type');
  }

  /** RFC 7009: either token revokes the whole grant. Unknown tokens are not an error. */
  revoke(p) {
    const row = this.db.prepare('SELECT grant_id FROM oauth_tokens WHERE token_hash = ?').get(sha256hex(String(p.token || '')));
    if (row) this.auth.revokeKey(row.grant_id);
  }

  register(body) {
    if (!this.dcrEnabled()) throw oauthErr(403, 'access_denied', 'Dynamic client registration is disabled on this instance');
    const uris = body.redirect_uris;
    if (!Array.isArray(uris) || !uris.length || !uris.every((u) => { try { const x = new URL(u); return x.protocol === 'https:' || (x.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(x.hostname)); } catch { return false; } })) {
      throw oauthErr(400, 'invalid_redirect_uri');
    }
    const id = newId('dcr', 24), name = String(body.client_name || 'Unnamed client').slice(0, 80);
    this.db.prepare('INSERT INTO oauth_clients (client_id,client_name,redirect_uris_json,created_at) VALUES (?,?,?,?)').run(id, name, JSON.stringify(uris), now());
    return { client_id: id, client_name: name, redirect_uris: uris, token_endpoint_auth_method: 'none' };
  }
}

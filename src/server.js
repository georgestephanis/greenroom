// node:http server: /s/* spaces, /api/* JSON + form API, server-rendered dashboard.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { CAS } from './cas.js';
import { Store } from './store.js';
import { Auth, httpErr, can, requireSession, requireAdmin, SESSION_COOKIE, normaliseScope, scopeString } from './auth.js';
import { OAuth } from './oauth.js';
import { createMcp } from './mcp.js';
import { applyDashboardHeaders, checkWrite, DASHBOARD_CSP } from './security.js';
import { createSpaceHandler } from './serve.js';
import { importZip } from './zip.js';
import { newId, now, randomToken, sha256hex } from './util.js';
import * as ui from './dashboard.js';

const html = (res, status, body) => { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.statusCode = status; res.end(body); };
const json = (res, status, obj) => { res.setHeader('Content-Type', 'application/json'); res.statusCode = status; res.end(JSON.stringify(obj)); };
const redirect = (res, to, status = 303) => { res.setHeader('Location', to); res.statusCode = status; res.end(); };
const safeNext = (n) => (typeof n === 'string' && n.startsWith('/') && !n.startsWith('//') && !n.startsWith('/\\') ? n : '/');

async function readBody(req, limit) {
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > limit) throw httpErr(413, 'Request body too large');
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

export function createApp(overrides = {}) {
  const config = loadConfig(process.env, overrides);
  fs.mkdirSync(config.tmpDir, { recursive: true });
  const db = openDb(config.dbFile);
  const cas = new CAS(config.blobsDir, config.tmpDir);
  const store = new Store(db, cas, config);
  const auth = new Auth(db, config);
  const handleSpace = createSpaceHandler({ store, auth, config });
  const oauth = new OAuth({ db, auth, config });
  const mcp = createMcp({ store, db });

  // Login throttle: in memory, pruned on access (no timers). Per account+IP, 10 attempts per 15 minutes.
  // Counted before the scrypt await so parallel attempts can't slip past; a success clears it.
  const attempts = new Map();
  const attempt = (key) => {
    const t = Date.now();
    if (attempts.size > 1000) for (const [k, v] of attempts) if (v.reset < t) attempts.delete(k);
    const f = attempts.get(key);
    if (f && f.reset > t) return ++f.n > 10;
    attempts.set(key, { n: 1, reset: t + 15 * 60e3 });
    return false;
  };
  const clientIp = (req) => (config.trustProxy && String(req.headers['x-forwarded-for'] || '').split(',').pop().trim()) || req.socket.remoteAddress;

  const sessionCookie = (s) => `${SESSION_COOKIE}=${s.cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=${new Date(s.expires).toUTCString()}`;
  const clearCookie = `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

  function slugSpace(cred, slug, perm) {
    const space = store.space(slug);
    if (!space || !can(cred, 'read', slug)) throw httpErr(404, 'No such space');
    if (perm && !can(cred, perm, slug)) throw httpErr(403, `Your credential cannot ${perm} here`);
    return space;
  }

  // ---- API: returns { status, body, next } ----
  async function api(req, res, url, cred, body) {
    const seg = url.pathname.split('/').slice(2); // after /api
    const m = req.method === 'POST' && body._method ? String(body._method).toUpperCase() : req.method;
    const ip = clientIp(req);
    const [a, b, c] = seg;

    if (a === 'setup' && m === 'POST') {
      // Same race as invites: claim first-run setup before the scrypt await.
      if (auth.userCount() || db.prepare("INSERT OR IGNORE INTO meta (key,value) VALUES ('setup_claimed', ?)").run(now()).changes !== 1) throw httpErr(403, 'Already set up');
      let u;
      try { u = await auth.createUser({ email: body.email, password: body.password, role: 'admin', name: body.name }); }
      catch (e) { db.prepare("DELETE FROM meta WHERE key = 'setup_claimed'").run(); throw e; }
      res.setHeader('Set-Cookie', sessionCookie(auth.createSession(u.id, { userAgent: req.headers['user-agent'], ip })));
      return { status: 201, body: { ok: true }, next: '/' };
    }
    if (a === 'login' && m === 'POST') {
      const key = `${String(body.email || '').toLowerCase()}|${ip}`;
      if (attempt(key)) throw httpErr(429, 'Too many attempts, try again later');
      const s = await auth.login(body.email, body.password, { userAgent: req.headers['user-agent'], ip });
      attempts.delete(key);
      res.setHeader('Set-Cookie', sessionCookie(s));
      return { status: 200, body: { ok: true }, next: safeNext(body._next) };
    }
    if (a === 'invites' && b === 'accept' && m === 'POST') {
      const inv = db.prepare('SELECT * FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?').get(sha256hex(String(body.token || '')), now());
      // Claim before the (slow) scrypt await, so parallel accepts can't each create an account.
      if (!inv || db.prepare('UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL').run(now(), inv.id).changes !== 1) throw httpErr(400, 'This invite is invalid or has expired');
      let u;
      try { u = await auth.createUser({ email: body.email, password: body.password, role: inv.role, name: body.name }); }
      catch (e) { db.prepare('UPDATE invites SET used_at = NULL WHERE id = ?').run(inv.id); throw e; }
      res.setHeader('Set-Cookie', sessionCookie(auth.createSession(u.id, { userAgent: req.headers['user-agent'], ip })));
      return { status: 201, body: { ok: true }, next: '/' };
    }

    if (!cred) throw httpErr(401, 'Sign in required');

    if (a === 'logout' && m === 'POST') {
      requireSession(cred);
      auth.revokeSession(cred.id);
      res.setHeader('Set-Cookie', clearCookie);
      return { status: 200, body: { ok: true }, next: '/login' };
    }
    if (a === 'me') return { status: 200, body: { user: { id: cred.userId, email: cred.user.username, role: cred.user.role }, credential: cred.type, scope: cred.scope } };

    // Escalation set: needs a person's own session (requireSession), never a scoped credential.
    if (a === 'invites' && m === 'POST') {
      requireAdmin(cred);
      const token = randomToken(24);
      db.prepare('INSERT INTO invites (id,token_hash,role,created_by,created_at,expires_at) VALUES (?,?,?,?,?,?)').run(
        newId('inv'), sha256hex(token), body.role === 'admin' ? 'admin' : 'member', cred.userId, now(), new Date(Date.now() + 7 * 864e5).toISOString());
      return { status: 201, body: { invite: `${config.publicUrl || `https://${req.headers.host}`}/invite/${token}` }, invite: true };
    }
    if (a === 'users' && c === 'disable' && m === 'POST') {
      requireAdmin(cred);
      if (b === cred.userId) throw httpErr(400, 'You cannot disable yourself');
      db.prepare('UPDATE users SET disabled_at = ? WHERE id = ?').run(now(), b);
      db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ?').run(now(), b);
      store.log(cred, 'user.disabled', null, { user: b });
      return { status: 200, body: { ok: true }, next: '/team' };
    }
    // Pasted agent tokens: minted and revoked only by a person (escalation set), same rows as OAuth grants.
    if (a === 'tokens' && !b && m === 'POST') {
      requireSession(cred);
      const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
      const scope = normaliseScope({ spaces: list(body.spaces).filter((s) => store.space(s)), create: body.create === '1' || body.create === true, perms: list(body.perms) });
      if (!scope) throw httpErr(400, 'Unknown permission');
      const token = 'fsa_' + randomToken(32), name = String(body.name || '').trim().slice(0, 80) || 'Agent token';
      db.prepare("INSERT INTO api_keys (id,name,key_hash,token_prefix,user_id,created_at,kind,scope_json) VALUES (?,?,?,?,?,?,'agent_token',?)")
        .run(newId('key'), name, sha256hex(token), token.slice(0, 12), cred.userId, now(), JSON.stringify(scope));
      return { status: 201, body: { token, name, scope: scopeString(scope) }, minted: token };
    }
    if (a === 'tokens' && c === 'revoke' && m === 'POST') {
      requireSession(cred);
      const row = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(b);
      if (!row || (row.user_id !== cred.userId && cred.user.role !== 'admin')) throw httpErr(404, 'No such token');
      auth.revokeKey(row.id);
      store.log(cred, 'token.revoked', null, { key: row.id });
      return { status: 200, body: { ok: true }, next: '/access' };
    }
    if (a === 'admin' && b === 'dcr' && m === 'POST') {
      requireAdmin(cred);
      oauth.setDcr(body.enabled === '1' || body.enabled === true);
      return { status: 200, body: { enabled: oauth.dcrEnabled() }, next: '/instance' };
    }
    if (a === 'admin' && b === 'gc' && m === 'POST') {
      requireAdmin(cred);
      const r = await store.maybeGc(true);
      return { status: 200, body: r ? await r : {}, next: '/instance?gc=1' };
    }

    if (a === 'spaces') {
      if (!b) {
        if (m === 'GET') return { status: 200, body: { spaces: store.listSpaces(cred.scope.spaces).map(pubSpace) } };
        if (m === 'POST') {
          if (!can(cred, 'create')) throw httpErr(403, 'Your credential cannot create spaces');
          const s = store.createSpace(cred, { name: body.name, slug: body.slug });
          return { status: 201, body: { space: pubSpace(s) }, next: body._next === '__space__' ? `/spaces/${s.slug}` : undefined };
        }
      } else {
        const perm = m === 'GET' ? null : 'publish';
        const space = slugSpace(cred, b, perm);
        if (!c) {
          if (m === 'GET') return { status: 200, body: { space: pubSpace(space) } };
          if (m === 'PATCH') {
            const patch = {};
            for (const k of ['name', 'slug', 'noindex']) if (body[k] !== undefined) patch[k] = body[k];
            if (body.privacy !== undefined) { requireSession(cred); patch.privacy = body.privacy; } // making Public is escalation
            return { status: 200, body: { space: pubSpace(store.updateSpace(cred, space, patch)) } };
          }
          if (m === 'DELETE') { requireSession(cred); store.deleteSpace(cred, space); return { status: 200, body: { ok: true }, next: '/' }; }
        }
        if (c === 'versions' && m === 'GET') return { status: 200, body: { versions: store.versions(space.id).map(pubVersion) } };
        if (c === 'versions' && m === 'POST') {
          const v = await store.publish(cred, space, { files: body.files, remove: body.remove, base: body.base, message: body.message, source: 'api' });
          return { status: 201, body: { version: pubVersion(v), warnings: v.warnings } };
        }
        if (c === 'diff' && m === 'GET') return { status: 200, body: store.diff(space, url.searchParams.get('from'), url.searchParams.get('to')) };
        if (c === 'rollback' && m === 'POST') {
          const v = await store.rollback(cred, space, body.version);
          return { status: 200, body: { version: pubVersion(v) } };
        }
      }
    }
    throw httpErr(404, 'Not found');
  }
  const pubSpace = (s) => ({ id: s.id, slug: s.slug, name: s.name, privacy: s.privacy, live_version_id: s.live_version_id, url: `/s/${s.slug}/` });
  const pubVersion = (v) => ({ id: v.id, number: v.number, message: v.message, author: v.author_name, source: v.source, files: v.total_files, bytes: v.total_bytes, created_at: v.created_at });

  // Raw zip upload: streamed to a tmp file, then unpacked entry by entry into CAS.
  async function upload(req, res, url, cred) {
    const slug = url.pathname.split('/')[3];
    const space = slugSpace(cred, slug, 'publish');
    const tmp = path.join(config.tmpDir, `up-${randomToken(8)}.zip`);
    try {
      let n = 0;
      await pipeline(req, async function* (src) {
        for await (const c of src) { n += c.length; if (n > config.maxUploadBytes) throw httpErr(413, 'Upload too large'); yield c; }
      }, fs.createWriteStream(tmp));
      const entries = await importZip(tmp, cas, config);
      const v = await store.createVersion(cred, space, entries, { message: url.searchParams.get('message') || 'Uploaded zip', source: 'ui' });
      return json(res, 201, { version: pubVersion(v), warnings: v.warnings });
    } finally {
      fs.rm(tmp, { force: true }, () => {});
    }
  }

  async function dashboard(req, res, url, cred) {
    const p = url.pathname;
    if (p === '/assets/app.js') { res.setHeader('Content-Type', 'text/javascript'); return res.end(ui.APP_JS); }
    if (p === '/assets/app.css') { res.setHeader('Content-Type', 'text/css'); return res.end(ui.APP_CSS); }
    if (p === '/login') return cred ? redirect(res, '/', 302) : html(res, 200, ui.authPage('Sign in', null, url.searchParams.get('error'), ui.loginFields, '/api/login', 'Sign in', `<input type="hidden" name="_next" value="${esc2(safeNext(url.searchParams.get('next')))}">`));
    if (p === '/setup') return auth.userCount() ? redirect(res, '/login', 302) : html(res, 200, ui.authPage('Set up freespace', null, url.searchParams.get('error'), ui.setupFields, '/api/setup', 'Create admin account'));
    let m = /^\/invite\/([\w-]+)$/.exec(p);
    if (m) return html(res, 200, ui.authPage('Join the team', null, url.searchParams.get('error'), ui.setupFields, '/api/invites/accept', 'Join', `<input type="hidden" name="token" value="${esc2(m[1])}">`));
    if (!cred || cred.type !== 'session') {
      if (!auth.userCount()) return redirect(res, '/setup', 302);
      return redirect(res, `/login?next=${encodeURIComponent(p + url.search)}`, 302);
    }
    if (p === '/oauth/authorize') {
      const q = Object.fromEntries(url.searchParams);
      let r;
      try { r = await oauth.checkRequest(q); } catch (e) { return html(res, 400, ui.messagePage(cred, 'Cannot connect this app', e.message)); }
      if (r.error) return redirect(res, oauth.redirectWith(r.redirect_uri, { error: r.error, error_description: r.desc, state: r.state }, req), 302);
      // CSP form-action must allow the post-consent redirect to the client, or browsers block it.
      const ru = new URL(r.redirect_uri);
      res.setHeader('Content-Security-Policy', DASHBOARD_CSP.replace("form-action 'self'", `form-action 'self' ${/^https?:$/.test(ru.protocol) ? ru.origin : ru.protocol}`));
      return html(res, 200, ui.consentPage(cred, r.client, q, r.requested, store.listSpaces()));
    }
    if (p === '/access') {
      const rows = db.prepare(`SELECT k.*, u.display_name AS granter FROM api_keys k JOIN users u ON u.id = k.user_id WHERE k.revoked_at IS NULL ${cred.user.role === 'admin' ? '' : 'AND k.user_id = ?'} ORDER BY k.created_at DESC`)
        .all(...(cred.user.role === 'admin' ? [] : [cred.userId]));
      return html(res, 200, ui.accessPage(cred, rows.map((r) => ({ ...r, scope: scopeString(JSON.parse(r.scope_json)) })), store.listSpaces()));
    }
    if (p === '/') return html(res, 200, ui.spacesPage(cred, store.listSpaces()));
    if (p === '/team') return html(res, 200, ui.teamPage(cred, db.prepare('SELECT * FROM users ORDER BY created_at').all(), db.prepare('SELECT COUNT(*) c FROM invites WHERE used_at IS NULL AND expires_at > ?').get(now()).c));
    if (p === '/instance') { requireAdmin(cred); return html(res, 200, ui.instancePage(cred, store.stats(), url.searchParams.get('gc') ? await store.gcPromise : null, oauth.dcrEnabled())); }
    m = /^\/spaces\/([^/]+)(\/diff)?$/.exec(p);
    if (m) {
      const space = store.space(m[1]);
      if (!space) return html(res, 404, ui.notFoundPage(cred));
      if (m[2]) {
        const d = store.diff(space, url.searchParams.get('from'), url.searchParams.get('to'));
        const texts = [];
        for (const f of [...d.added, ...d.changed, ...d.removed].slice(0, 20)) texts.push({ path: f.path, ops: await store.textDiff(space, d.from, d.to, f.path) });
        return html(res, 200, ui.diffPage(cred, space, d, texts));
      }
      const versions = store.versions(space.id);
      const live = versions.find((v) => v.id === space.live_version_id);
      return html(res, 200, ui.spacePage(cred, space, versions, live ? JSON.parse(live.warnings_json || '[]') : []));
    }
    return html(res, 404, ui.notFoundPage(cred));
  }
  const esc2 = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

  async function parseBody(req, isForm) {
    const raw = await readBody(req, isForm ? 1 << 20 : config.maxJsonBytes);
    if (!raw.length) return {};
    try {
      if (!isForm) return JSON.parse(raw.toString());
      const out = {};
      for (const [k, v] of new URLSearchParams(raw.toString())) out[k] = k in out ? [].concat(out[k], v) : v; // repeated keys -> array
      return out;
    } catch { throw httpErr(400, 'Malformed body'); }
  }

  // Token, revocation and registration endpoints: called by clients, never with a cookie, so no CSRF
  // check applies and cookies are ignored entirely.
  async function oauthEndpoint(req, res, url) {
    if (req.method !== 'POST') return json(res, 405, { error: 'invalid_request' });
    try {
      const body = await parseBody(req, (req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded'));
      if (url.pathname === '/oauth/token') return json(res, 200, oauth.token(body));
      if (url.pathname === '/oauth/revoke') { oauth.revoke(body); return json(res, 200, {}); }
      return json(res, 201, oauth.register(body));
    } catch (e) {
      if (!e.status) throw e;
      return json(res, e.status, { error: e.oauth || 'invalid_request', error_description: e.message });
    }
  }

  // MCP: Bearer only. A dashboard cookie never authenticates here.
  async function handleMcp(req, res) {
    const challenge = (extra = '') => `Bearer resource_metadata="${oauth.issuer(req)}/.well-known/oauth-protected-resource/mcp"${extra}`;
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return json(res, 405, { error: 'POST only (no SSE stream)' }); }
    const resolve = () => auth.resolve({ headers: { authorization: req.headers.authorization } });
    const unauthorized = () => { res.setHeader('WWW-Authenticate', challenge()); return json(res, 401, { error: 'Authentication required' }); };
    if (!resolve()) return unauthorized(); // cheap refusal before reading a body
    let msg;
    try { msg = JSON.parse((await readBody(req, config.maxJsonBytes)).toString()); } catch (e) { if (e.status) throw e; return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
    // Resolve again now the body is in: a grant revoked or re-consented while it trickled in must win.
    const cred = resolve();
    if (!cred) return unauthorized();
    const r = await mcp(cred, msg);
    if (r.insufficientScope) res.setHeader('WWW-Authenticate', challenge(`, error="insufficient_scope", scope="${r.insufficientScope}"`));
    if (!r.body) { res.statusCode = r.status; return res.end(); }
    return json(res, r.status, r.body);
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    try {
      if (url.pathname === '/s' || url.pathname.startsWith('/s/')) return await handleSpace(req, res, url);
      applyDashboardHeaders(res);
      if (url.pathname.startsWith('/.well-known/oauth-')) {
        if (/^\/\.well-known\/oauth-protected-resource(\/mcp)?$/.test(url.pathname)) return json(res, 200, oauth.protectedResource(req));
        if (url.pathname === '/.well-known/oauth-authorization-server') return json(res, 200, oauth.serverMetadata(req));
        return json(res, 404, { error: 'Not found' });
      }
      if (url.pathname === '/mcp') return await handleMcp(req, res);
      if (['/oauth/token', '/oauth/revoke', '/oauth/register'].includes(url.pathname)) return await oauthEndpoint(req, res, url);
      const cred = auth.resolve(req);
      const write = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
      if (!write && url.pathname.startsWith('/api/')) {
        const r = await api(req, res, url, cred, {});
        return json(res, r.status, r.body);
      }
      if (!write) return await dashboard(req, res, url, cred);

      const isUpload = /^\/api\/spaces\/[^/]+\/upload$/.test(url.pathname);
      const isForm = (req.headers['content-type'] || '').split(';')[0] === 'application/x-www-form-urlencoded';
      const body = isUpload ? {} : await parseBody(req, isForm);
      if (url.pathname === '/oauth/authorize') { // the person's consent: cookie session + CSRF like any dashboard form
        const refused = checkWrite(req, cred, body, config.publicUrl);
        if (refused) throw httpErr(403, refused);
        if (!cred) throw httpErr(401, 'Sign in required');
        return redirect(res, await oauth.approve(cred, body, req));
      }
      const refusal = checkWrite(req, cred, body, config.publicUrl);
      if (refusal) throw httpErr(403, refusal);
      if (isUpload) {
        if (!cred) throw httpErr(401, 'Sign in required');
        return await upload(req, res, url, cred);
      }
      if (!url.pathname.startsWith('/api/')) throw httpErr(404, 'Not found');
      const r = await api(req, res, url, cred, body);
      if (isForm) {
        if (r.minted) return html(res, 201, ui.accessPage(cred, [], store.listSpaces(), r.minted));
        if (r.invite) return html(res, 201, ui.teamPage(cred, db.prepare('SELECT * FROM users ORDER BY created_at').all(), 1, r.body.invite));
        return redirect(res, safeNext(r.next));
      }
      return json(res, r.status, r.body);
    } catch (e) {
      const status = e.status || 500;
      if (status === 500) console.error(e);
      if (res.headersSent) return res.destroy();
      const isForm = (req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded');
      const back = req.headers.referer ? new URL(req.headers.referer, 'http://x') : null;
      if (isForm && status < 500 && status !== 403 && back && back.pathname !== '/') {
        back.searchParams.set('error', e.message);
        return redirect(res, back.pathname + back.search);
      }
      return json(res, status, { error: status === 500 ? 'Internal error' : e.message });
    }
  });
  server.keepAliveTimeout = 5000;
  return { server, store, auth, config, db };
}

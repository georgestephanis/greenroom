// node:http server: /s/* spaces, /api/* JSON + form API, server-rendered dashboard.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { CAS } from './cas.js';
import { Store } from './store.js';
import { People } from './people.js';
import { Auth, httpErr, can, requireSession, requireAdmin, SESSION_COOKIE, normaliseScope, scopeString } from './auth.js';
import { OAuth } from './oauth.js';
import { createMcp } from './mcp.js';
import { applyDashboardHeaders, checkWrite, DASHBOARD_CSP } from './security.js';
import { createSpaceHandler } from './serve.js';
import { importZip } from './zip.js';
import { exportBundle, importBundle, verifyExport } from './bundle.js';
import { newId, now, randomToken, sha256hex } from './util.js';
import * as ui from './dashboard.js';
import { createPlugins } from './plugins.js';
import { startMigration, jobView } from './migrate.js';

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
  const oauth = new OAuth({ db, auth, config });
  // Plugins: the bundled sqlite and watermark plus any in config.plugins (definitions, loaded by bin/greenroom.js).
  const plugins = createPlugins({ store, config, installed: config.plugins ?? [] });
  store.plugins = plugins;
  const mcp = createMcp({ store, db, plugins });

  // Login throttle: in memory, pruned on access (no timers). Per account+IP, 10 attempts per 15 minutes.
  // Counted before the scrypt await so parallel attempts can't slip past; a success clears it.
  let migration = null; // the one Move to Spacefast job (src/migrate.js)
  const attempts = new Map();
  const attempt = (key, max = 10, windowMs = 15 * 60e3) => {
    const t = Date.now();
    if (attempts.size > 1000) for (const [k, v] of attempts) if (v.reset < t) attempts.delete(k);
    const f = attempts.get(key);
    if (f && f.reset > t) return ++f.n > max;
    attempts.set(key, { n: 1, reset: t + windowMs });
    return false;
  };
  const clientIp = (req) => (config.trustProxy && String(req.headers['x-forwarded-for'] || '').split(',').pop().trim()) || req.socket.remoteAddress;
  const people = new People({ db, auth, store, config, throttle: attempt });
  const handleSpace = createSpaceHandler({ store, auth, config, clientIp, plugins, throttle: { hit: attempt, clear: (k) => attempts.delete(k) } });
  const origin = (req) => oauth.issuer(req);
  const teamUsers = () => db.prepare('SELECT * FROM users ORDER BY created_at').all().map((u) => ({ ...u, lapsed: !u.disabled_at && auth.lapsed(u) }));
  const pubLink = (req, space, g) => ({
    id: g.id, label: g.name, url: g.key ? `${origin(req)}/s/${space.slug}/?key=${g.key}` : null, hint: g.token_hint, password: !!g.secret_hash,
    expires_at: g.expires_at, max_uses: g.max_uses, uses: g.uses_count, revoked_at: g.revoked_at, disabled_at: g.disabled_at,
    active: store.linkLive(space, g), view_count: g.view_count, first_viewed_at: g.first_viewed_at, last_viewed_at: g.last_viewed_at, created_at: g.created_at,
  });

  // What the dashboard and GET /api/spaces/:slug/plugins show for a space.
  const pluginRows = (space) => {
    const on = plugins.listed(space);
    return [
      ...plugins.names().map((n) => ({ ...plugins.info(n), installed: true, instance_enabled: plugins.instanceEnabled(n), enabled: on.includes(n), settings: plugins.settings(space, n), spec: plugins.spec(n) })),
      ...on.filter((n) => !plugins.installed(n)).map((n) => ({ name: n, installed: false, instance_enabled: false, enabled: true, settings: {}, spec: {} })),
    ];
  };
  const flag = (v) => (v === undefined ? undefined : v === true || v === '1' || v === 'true');
  // The dashboard form sends one s_{key} field per setting; JSON callers send `settings` directly.
  const formSettings = (spec, body) => {
    const out = {};
    for (const [k, sp] of Object.entries(spec)) {
      const v = body[`s_${k}`];
      if (v === undefined) continue;
      out[k] = sp.type === 'number' ? Number(v) : sp.type === 'bool' ? flag(v)
        : sp.type === 'map' ? Object.fromEntries(String(v).split('\n').map((l) => l.trim()).filter(Boolean).map((l) => l.split(/\s*[:=]\s*/))) : v;
    }
    return Object.keys(out).length ? out : undefined;
  };

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
      let s;
      try { s = await auth.login(body.email, body.password, { userAgent: req.headers['user-agent'], ip }); }
      catch (e) { if (e.lapsedUser) people.sendReconfirm(e.lapsedUser); throw e; }
      attempts.delete(key);
      res.setHeader('Set-Cookie', sessionCookie(s));
      return { status: 200, body: { ok: true }, next: safeNext(body._next) };
    }
    if (a === 'invites' && b === 'accept' && m === 'POST') {
      const inv = db.prepare('SELECT * FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?').get(sha256hex(String(body.token || '')), now());
      // The inviter is a live constraint like any granter: a deactivated or lapsed admin's invites are dead.
      // Claim before the (slow) scrypt await, so parallel accepts can't each create an account.
      if (!inv || !auth.activeUser(inv.created_by) || db.prepare('UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL').run(now(), inv.id).changes !== 1) throw httpErr(400, 'This invite is invalid or has expired');
      let u;
      try { u = await auth.createUser({ email: body.email, password: body.password, role: inv.role, name: body.name }); }
      catch (e) { db.prepare('UPDATE invites SET used_at = NULL WHERE id = ?').run(inv.id); throw e; }
      res.setHeader('Set-Cookie', sessionCookie(auth.createSession(u.id, { userAgent: req.headers['user-agent'], ip })));
      return { status: 201, body: { ok: true }, next: '/' };
    }

    // Self-signup and re-confirmation (M6). Same answer for every well-formed address; mail is sent off the request path.
    if (a === 'signup' && !b && m === 'POST') {
      if (attempt(`signup-ip|${ip}`, 10, 60 * 60e3)) throw httpErr(429, 'Too many attempts, try again later');
      people.requestSignup(body.email);
      return { status: 202, body: { ok: true, message: 'Check your inbox' }, next: '/signup?sent=1' };
    }
    if (a === 'signup' && b === 'complete' && m === 'POST') {
      const u = await people.completeSignup({ token: body.token, name: body.name, password: body.password });
      res.setHeader('Set-Cookie', sessionCookie(auth.createSession(u.id, { userAgent: req.headers['user-agent'], ip })));
      return { status: 201, body: { ok: true }, next: '/' };
    }
    if (a === 'confirm' && m === 'POST') {
      people.confirm(body.token);
      return { status: 200, body: { ok: true }, next: '/login?confirmed=1' };
    }

    if (!cred) throw httpErr(401, 'Sign in required');

    if (a === 'logout' && m === 'POST') {
      requireSession(cred);
      auth.revokeSession(cred.id);
      res.setHeader('Set-Cookie', clearCookie);
      return { status: 200, body: { ok: true }, next: '/login' };
    }
    // A person's own account: their session only, never an agent token acting as them.
    if (a === 'account' && !b && m === 'POST') {
      requireSession(cred);
      auth.setName(cred.userId, body.name);
      store.log(cred, 'account.updated', null, {});
      return { status: 200, body: { ok: true }, next: '/account?saved=name' };
    }
    if (a === 'account' && b === 'password' && m === 'POST') {
      requireSession(cred);
      if (attempt(`password|${cred.userId}`)) throw httpErr(429, 'Too many attempts, try again later');
      await auth.changePassword(cred.userId, body.current, body.password, cred.id);
      attempts.delete(`password|${cred.userId}`);
      store.log(cred, 'account.password_changed', null, {});
      return { status: 200, body: { ok: true }, next: '/account?saved=password' };
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
    // Offboarding: Auth.activeUser is the live granter check behind every credential (session, pasted key,
    // OAuth access and refresh), so setting disabled_at stops them all at once. Nothing they made is deleted.
    if (a === 'users' && (c === 'deactivate' || c === 'reactivate') && m === 'POST') {
      requireAdmin(cred);
      const u = db.prepare('SELECT * FROM users WHERE id = ?').get(b);
      if (!u) throw httpErr(404, 'No such user');
      if (c === 'deactivate') {
        const others = db.prepare("SELECT id FROM users WHERE role = 'admin' AND disabled_at IS NULL AND id != ?").all(b);
        if (u.role === 'admin' && !u.disabled_at && !others.some((o) => auth.activeUser(o.id))) throw httpErr(400, 'The last active admin cannot be deactivated');
        db.prepare('UPDATE users SET disabled_at = COALESCE(disabled_at, ?) WHERE id = ?').run(now(), b);
        db.prepare('UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ?').run(now(), b); // reactivation won't revive them
        db.prepare('UPDATE invites SET used_at = ? WHERE created_by = ? AND used_at IS NULL').run(now(), b); // nor their open invites
      } else db.prepare('UPDATE users SET disabled_at = NULL WHERE id = ?').run(b);
      store.log(cred, `user.${c}d`, null, { user: b });
      return { status: 200, body: { ok: true }, next: b === cred.userId ? '/login' : '/team' };
    }
    // Pasted agent tokens: minted and revoked only by a person (escalation set), same rows as OAuth grants.
    if (a === 'tokens' && !b && m === 'POST') {
      requireSession(cred);
      const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
      const scope = normaliseScope({ spaces: list(body.spaces).filter((s) => store.space(s)), create: body.create === '1' || body.create === true, perms: list(body.perms) });
      if (!scope) throw httpErr(400, 'Unknown permission');
      const token = 'gra_' + randomToken(32), name = String(body.name || '').trim().slice(0, 80) || 'Agent token';
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
    if (a === 'admin' && b === 'branding' && m === 'POST') {
      requireAdmin(cred);
      return { status: 200, body: { branding: store.setBranding(cred, body) }, next: '/instance' };
    }
    if (a === 'admin' && b === 'plugins' && c && m === 'POST') {
      requireAdmin(cred);
      plugins.setInstanceEnabled(c, flag(body.enabled) ?? true);
      store.log(cred, flag(body.enabled) === false ? 'plugin.disabled' : 'plugin.enabled', null, { plugin: c });
      return { status: 200, body: { ok: true }, next: '/instance' };
    }
    if (a === 'admin' && b === 'smtp' && !c && m === 'POST') { requireAdmin(cred); people.setSmtp(cred, body, origin(req)); return { status: 200, body: people.view(), next: '/instance#people' }; }
    if (a === 'admin' && b === 'smtp' && c === 'test' && m === 'POST') { requireAdmin(cred); await people.test(cred); return { status: 200, body: { ok: true }, next: '/instance?mailed=1#people' }; }
    if (a === 'admin' && b === 'signup' && m === 'POST') { requireAdmin(cred); people.setSignup(cred, body); return { status: 200, body: people.view(), next: '/instance#people' }; }
    if (a === 'admin' && b === 'reconfirm' && m === 'POST') { requireAdmin(cred); people.setReconfirm(cred, body); return { status: 200, body: people.view(), next: '/instance#people' }; }
    // Move to Spacefast (or homefast): the token comes in on this request and stays in the job's closure.
    if (a === 'admin' && b === 'migrate' && m === 'GET') { requireAdmin(cred); return { status: 200, body: { migration: jobView(migration) } }; }
    if (a === 'admin' && b === 'migrate' && m === 'POST') {
      requireAdmin(cred);
      if (migration && !migration.done) throw httpErr(409, 'A move is already running');
      const slugs = body.spaces === undefined ? [] : [].concat(body.spaces);
      migration = startMigration({ store, cas, tls: config.outboundTls }, { url: body.url, token: body.token, slugs, history: flag(body.history) });
      store.log(cred, 'instance.migrate', null, { target: migration.target, spaces: migration.spaces.length, history: migration.history });
      return { status: 202, body: { migration: jobView(migration) }, next: '/instance/migrate' };
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
        const perm = m === 'GET' || c === 'links' ? null : 'publish';
        const space = slugSpace(cred, b, perm);
        if (c === 'links') {
          if (!can(cred, 'share', space.slug)) throw httpErr(403, 'Your credential cannot manage share links here');
          const next = `/spaces/${space.slug}#sharing`;
          if (!seg[3] && m === 'GET') return { status: 200, body: { links: store.links(space).map((g) => pubLink(req, space, g)) } };
          if (!seg[3] && m === 'POST') {
            const g = await store.createLink(cred, space, { label: body.label, expires_at: body.expires_at, expires_in: body.expires_in, password: body.password, max_uses: body.max_uses });
            const link = pubLink(req, store.spaceById(space.id), g);
            return { status: 201, body: { link }, shownOnce: { title: 'New share link', value: link.url, back: next } };
          }
          if (seg[3] && seg[4] === 'resume' && m === 'POST') { requireSession(cred); return { status: 200, body: { link: pubLink(req, space, store.resumeLink(cred, space, seg[3])) }, next }; }
          if (seg[3] && seg[4] === 'revoke' && m === 'POST') return { status: 200, body: { link: pubLink(req, space, store.revokeLink(cred, space, seg[3])) }, next };
          throw httpErr(404, 'Not found');
        }
        if (!c) {
          if (m === 'GET') return { status: 200, body: { space: pubSpace(space) } };
          if (m === 'PATCH') {
            const patch = {};
            for (const k of ['name', 'slug', 'noindex']) if (body[k] !== undefined) patch[k] = body[k];
            if (body.privacy !== undefined) {
              if (body.privacy === 'public') requireSession(cred); // making Public is a person's decision (section 6)
              else if (!can(cred, 'share', space.slug)) throw httpErr(403, 'Your credential cannot change sharing here');
              patch.privacy = body.privacy;
            }
            return { status: 200, body: { space: pubSpace(store.updateSpace(cred, space, patch)) }, next: `/spaces/${space.slug}` };
          }
          if (m === 'DELETE') { requireSession(cred); store.deleteSpace(cred, space); return { status: 200, body: { ok: true }, next: '/' }; }
        }
        // Per-space plugin switches and settings are a person's call: session only, like sharing.
        if (c === 'plugins' && !seg[3] && m === 'GET') return { status: 200, body: { plugins: pluginRows(space) } };
        if (c === 'plugins' && seg[3] && ['PUT', 'PATCH', 'POST'].includes(m)) {
          requireSession(cred);
          const spec = plugins.spec(seg[3]);
          plugins.configure(space, seg[3], { enabled: flag(body.enabled), settings: body.settings ?? formSettings(spec, body) });
          store.log(cred, 'plugin.configured', space.id, { plugin: seg[3], enabled: flag(body.enabled) });
          return { status: 200, body: { plugins: pluginRows(store.spaceById(space.id)) }, next: `/spaces/${space.slug}#plugins` };
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

  // Raw zip body streamed to a tmp file (capped), never held in memory.
  async function spool(req, cap = config.maxUploadBytes) {
    const tmp = path.join(config.tmpDir, `up-${randomToken(8)}.zip`);
    let n = 0;
    try {
      await pipeline(req, async function* (src) {
        for await (const c of src) { n += c.length; if (n > cap) throw httpErr(413, 'Upload too large'); yield c; }
      }, fs.createWriteStream(tmp));
    } catch (e) { fs.rmSync(tmp, { force: true }); throw e; }
    return tmp;
  }

  // Raw zip upload: spooled to disk, then unpacked entry by entry into CAS.
  async function upload(req, res, url, cred) {
    const slug = url.pathname.split('/')[3];
    const space = slugSpace(cred, slug, 'publish');
    const tmp = await spool(req);
    try {
      const entries = await importZip(tmp, cas, config);
      const v = await store.createVersion(cred, space, entries, { message: url.searchParams.get('message') || 'Uploaded zip', source: 'ui' });
      return json(res, 201, { version: pubVersion(v), warnings: v.warnings });
    } finally {
      fs.rm(tmp, { force: true }, () => {});
    }
  }

  // Import a greenroom bundle as a new space. A person's act (like deleting or going public), never an agent's.
  let importing = 0; // one at a time: an import holds a spooled zip and a long transaction
  async function importSpace(req, res, url, cred) {
    requireSession(cred);
    const replace = url.searchParams.get('replace') === '1';
    if (importing >= 1) { res.setHeader('Retry-After', '10'); throw httpErr(503, 'Another import is running; try again shortly'); }
    importing++;
    let tmp;
    try {
      tmp = await spool(req, config.maxImportBytes);
      const r = await importBundle(store, cred, tmp, { slug: url.searchParams.get('slug') || undefined, replace });
      return json(res, 201, { space: pubSpace(r.space), versions: r.versions, warnings: r.warnings, remapped: r.remapped });
    } finally {
      importing--;
      if (tmp) fs.rm(tmp, { force: true }, () => {});
    }
  }

  // Exports are built on disk and streamed out; at most two at once keeps a 1 GB box safe.
  let exporting = 0;
  async function sendExport(res, cred, space, history) {
    if (exporting >= 2) { res.setHeader('Retry-After', '10'); throw httpErr(503, 'Too many exports running; try again shortly'); }
    exporting++;
    const tmp = path.join(config.tmpDir, `exp-${randomToken(8)}.zip`);
    try {
      await exportBundle(store, space, { history, outFile: tmp });
      store.log(cred, 'space.exported', space.id, { history }, { type: 'space', id: space.id });
      res.writeHead(200, {
        'Content-Type': 'application/zip', 'Content-Length': fs.statSync(tmp).size,
        'Content-Disposition': `attachment; filename="${space.slug}.greenroom${history ? '-history' : ''}.zip"`,
      });
      await pipeline(fs.createReadStream(tmp), res);
    } finally {
      exporting--;
      fs.rm(tmp, { force: true }, () => {});
    }
  }

  async function dashboard(req, res, url, cred) {
    const p = url.pathname;
    if (p === '/assets/app.js') { res.setHeader('Content-Type', 'text/javascript'); return res.end(ui.APP_JS); }
    if (p === '/assets/app.css') { res.setHeader('Content-Type', 'text/css'); return res.end(ui.APP_CSS); }
    if (p === '/login') return cred ? redirect(res, '/', 302) : html(res, 200, ui.authPage('Sign in', null, url.searchParams.get('error'), ui.loginFields + (people.signupOpen() ? '<p><small>New here? <a href="/signup">Sign up with your work email</a></small></p>' : ''), '/api/login', 'Sign in', `${url.searchParams.get('confirmed') ? '<p class="ok">Email confirmed. Sign in to continue.</p>' : ''}<input type="hidden" name="_next" value="${esc2(safeNext(url.searchParams.get('next')))}">`));
    if (p === '/setup') return auth.userCount() ? redirect(res, '/login', 302) : html(res, 200, ui.authPage('Set up greenroom', null, url.searchParams.get('error'), ui.setupFields, '/api/setup', 'Create admin account'));
    let m = /^\/invite\/([\w-]+)$/.exec(p);
    if (m) return html(res, 200, ui.authPage('Join the team', null, url.searchParams.get('error'), ui.setupFields, '/api/invites/accept', 'Join', `<input type="hidden" name="token" value="${esc2(m[1])}">`));
    if (p === '/signup') return people.signupOpen() ? html(res, 200, ui.signupPage(cred, url.searchParams.get('sent'), url.searchParams.get('error'))) : html(res, 404, ui.messagePage(null, 'Not available', 'Self-signup is not turned on here. Ask an admin for an invite.'));
    m = /^\/signup\/([\w-]+)$/.exec(p);
    if (m) return html(res, 200, ui.authPage('Create your account', cred, url.searchParams.get('error') || (people.peek('signup', m[1]) ? null : 'This link is invalid or has expired'), ui.signupFields, '/api/signup/complete', 'Create account', `<input type="hidden" name="token" value="${esc2(m[1])}">`));
    m = /^\/confirm\/([\w-]+)$/.exec(p); // a button, not a GET side effect, so mail scanners can't spend the link
    if (m) return html(res, 200, ui.authPage('Confirm your email', cred, url.searchParams.get('error') || (people.peek('reconfirm', m[1]) ? null : 'This link is invalid or has expired'), '', '/api/confirm', 'Confirm', `<input type="hidden" name="token" value="${esc2(m[1])}">`));
    if (!cred || cred.type !== 'session') {
      if (!auth.userCount()) return redirect(res, '/setup', 302);
      return redirect(res, `/login?next=${encodeURIComponent(p + url.search)}`, 302);
    }
    if (p === '/oauth/authorize') {
      const q = Object.fromEntries(url.searchParams);
      let r;
      try { r = await oauth.checkRequest(q); } catch (e) { return html(res, 400, ui.messagePage(cred, 'Cannot connect this app', e.message)); }
      const prev = db.prepare("SELECT scope_json FROM api_keys WHERE kind = 'oauth' AND user_id = ? AND client_id = ? AND revoked_at IS NULL").get(cred.userId, r.client.client_id);
      if (r.error) {
        // Anyone can publish a CIMD document listing any redirect_uri, so error redirects would be an open
        // redirect (RFC 9700 4.11.2). Only redirect to a client this member has already approved.
        if (prev) return redirect(res, oauth.redirectWith(r.redirect_uri, { error: r.error, error_description: r.desc, state: r.state }, req), 302);
        return html(res, 400, ui.messagePage(cred, 'Cannot connect this app', `${r.error}${r.desc ? `: ${r.desc}` : ''}`));
      }
      // CSP form-action must allow the post-consent redirect to the client, or browsers block it.
      const ru = new URL(r.redirect_uri);
      res.setHeader('Content-Security-Policy', DASHBOARD_CSP.replace("form-action 'self'", `form-action 'self' ${/^https?:$/.test(ru.protocol) ? ru.origin : ru.protocol}`));
      // Approval replaces the grant's scope, so start from what this member already granted this client.
      const was = prev ? JSON.parse(prev.scope_json) : { spaces: [], create: false, perms: [] };
      const pick = {
        spaces: [...new Set([...(was.spaces === '*' ? [] : was.spaces), ...r.requested.spaces])],
        create: was.create || r.requested.create,
        perms: [...new Set([...was.perms, ...r.requested.perms])],
      };
      return html(res, 200, ui.consentPage(cred, r.client, q, pick, store.listSpaces()));
    }
    if (p === '/access') {
      const rows = db.prepare(`SELECT k.*, u.display_name AS granter FROM api_keys k JOIN users u ON u.id = k.user_id WHERE k.revoked_at IS NULL ${cred.user.role === 'admin' ? '' : 'AND k.user_id = ?'} ORDER BY k.created_at DESC`)
        .all(...(cred.user.role === 'admin' ? [] : [cred.userId]));
      return html(res, 200, ui.accessPage(cred, rows.map((r) => ({ ...r, scope: scopeString(JSON.parse(r.scope_json)) })), store.listSpaces()));
    }
    if (p === '/') return html(res, 200, ui.spacesPage(cred, store.listSpaces()));
    if (p === '/account') { requireSession(cred); return html(res, 200, ui.accountPage(cred, url.searchParams.get('saved'), url.searchParams.get('error'))); }
    if (p === '/team') return html(res, 200, ui.teamPage(cred, teamUsers(), db.prepare('SELECT COUNT(*) c FROM invites WHERE used_at IS NULL AND expires_at > ?').get(now()).c));
    if (p === '/instance/migrate') { requireAdmin(cred); return html(res, 200, ui.migratePage(cred, store.listSpaces(), jobView(migration), url.searchParams.get('error'))); }
    if (p === '/instance') { requireAdmin(cred); return html(res, 200, ui.instancePage(cred, store.stats(), url.searchParams.get('gc') ? await store.gcPromise : null, oauth.dcrEnabled(), store.branding(), plugins.names().map((n) => ({ ...plugins.info(n), on: plugins.instanceEnabled(n) })), { ...people.view(), mailed: url.searchParams.get('mailed') })); }
    m = /^\/spaces\/([^/]+)\/export$/.exec(p);
    if (m) {
      const space = store.space(m[1]);
      if (!space) return html(res, 404, ui.notFoundPage(cred));
      return sendExport(res, cred, space, url.searchParams.get('history') === '1');
    }
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
      const links = can(cred, 'share', space.slug) ? store.links(space).map((g) => pubLink(req, space, g)) : null;
      return html(res, 200, ui.spacePage(cred, space, versions, live ? JSON.parse(live.warnings_json || '[]') : [], links, can(cred, 'publish', space.slug) ? pluginRows(space) : []));
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
    const r = await mcp(cred, msg, oauth.issuer(req));
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
      // Signed download link from the MCP export_space tool: the signature is the credential.
      const ex = req.method === 'GET' && /^\/export\/(spc_[\w-]+)\/(current|history)$/.exec(url.pathname);
      if (ex) {
        // Signed for this space id and credential; both must still be live and the credential must still be allowed to export.
        const credId = url.searchParams.get('c');
        const space = verifyExport(config.secret, ex[1], credId, ex[2], url.searchParams.get('exp'), url.searchParams.get('sig')) && store.spaceById(ex[1]);
        const holder = space && !space.archived_at ? auth.keyCred(credId) : null;
        if (!holder || !can(holder, 'export', space.slug)) return json(res, 404, { error: 'This download link is invalid or has expired' });
        return await sendExport(res, holder, space, ex[2] === 'history');
      }
      const cred = auth.resolve(req);
      const write = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
      if (!write && url.pathname.startsWith('/api/')) {
        const r = await api(req, res, url, cred, {});
        return json(res, r.status, r.body);
      }
      if (!write) return await dashboard(req, res, url, cred);

      const isImport = url.pathname === '/api/import';
      const isUpload = isImport || /^\/api\/spaces\/[^/]+\/upload$/.test(url.pathname);
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
        return await (isImport ? importSpace : upload)(req, res, url, cred);
      }
      if (!url.pathname.startsWith('/api/')) throw httpErr(404, 'Not found');
      const r = await api(req, res, url, cred, body);
      if (isForm) {
        if (r.shownOnce) return html(res, 201, ui.shownOnce(cred, r.shownOnce));
        if (r.minted) return html(res, 201, ui.accessPage(cred, [], store.listSpaces(), r.minted));
        if (r.invite) return html(res, 201, ui.teamPage(cred, teamUsers(), 1, r.body.invite));
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
  return { server, store, auth, config, db, plugins, people };
}

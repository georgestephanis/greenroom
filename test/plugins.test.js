// M5: plugin loader, per-space enablement, the sqlite plugin and the watermark plugin (issue #214 section 11).
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { boot, client, setupAdmin } from './helpers.js';
import { definePlugin } from '../src/plugins.js';
import { withZip, ZipWriter } from '../src/zip.js';
import { DatabaseSync } from 'node:sqlite';

const DOC = { 'sec-fetch-dest': 'document' };
const files = (o) => Object.entries(o).map(([p, content]) => ({ path: p, content }));
const PAGE = '<html><head></head><body><h1>hi</h1></body></html>';

async function world(x, { enable = ['sqlite', 'watermark'], on = ['sqlite', 'watermark'], overrides } = {}) {
  const t = await boot(overrides); x.after(t.close);
  const admin = await setupAdmin(t);
  await admin.post('/api/spaces', { name: 'Demo', slug: 'demo' });
  assert.equal((await admin.post('/api/spaces/demo/versions', { files: files({ 'index.html': PAGE, 'a.css': 'x{}' }) })).status, 201);
  for (const n of enable) assert.equal((await admin.post(`/api/admin/plugins/${n}`, { enabled: true })).status, 200);
  for (const n of on) assert.equal((await admin.post(`/api/spaces/demo/plugins/${n}`, { enabled: true }, 'PUT')).status, 200);
  return { t, admin };
}
const mcp = async (t, token, name, args = {}) => {
  const r = await fetch(t.base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
  return { status: r.status, body: await r.json() };
};
const token = async (admin, perms) => (await (await admin.post('/api/tokens', { name: 't' + perms.join(''), spaces: ['demo'], perms })).json()).token;
const sc = (r) => r.body.result?.structuredContent;

// ------------------------------------------------------------------ loader

test('loader: plugins are off until an admin enables them, and a space opts in separately', async (x) => {
  const { t, admin } = await world(x, { enable: [], on: [] });
  assert.equal((await admin.post('/api/spaces/demo/plugins/watermark', { enabled: true }, 'PUT')).status, 409, 'not enabled on the instance');
  await admin.post('/api/admin/plugins/watermark', { enabled: true });
  await admin.post('/api/spaces/demo/plugins/watermark', { enabled: true }, 'PUT');
  assert.deepEqual(t.plugins.active(t.store.space('demo')), ['watermark']);
  await admin.post('/api/admin/plugins/watermark', { enabled: false });
  assert.deepEqual(t.plugins.active(t.store.space('demo')), [], 'instance off beats space on');
  const list = await (await admin.fetch('/api/spaces/demo/plugins')).json();
  assert.deepEqual(list.plugins.map((p) => [p.name, p.enabled, p.instance_enabled]), [['sqlite', false, false], ['watermark', true, false]]);
});

test('loader: only an admin enables at the instance level, only a session configures a space', async (x) => {
  const { t, admin } = await world(x, { enable: [], on: [] });
  const tok = await token(admin, ['publish', 'db', 'share', 'export', 'read']);
  const bearer = { authorization: `Bearer ${tok}`, 'content-type': 'application/json' };
  assert.equal((await fetch(t.base + '/api/admin/plugins/watermark', { method: 'POST', headers: bearer, body: '{"enabled":true}' })).status, 403);
  assert.equal(t.plugins.instanceEnabled('watermark'), false);
  await admin.post('/api/admin/plugins/watermark', { enabled: true });
  assert.equal((await fetch(t.base + '/api/spaces/demo/plugins/watermark', { method: 'PUT', headers: bearer, body: '{"enabled":true}' })).status, 403);
});

test('loader: a plugin sees a narrow ctx, never core tables or credentials', async (x) => {
  let seen;
  const spy = definePlugin({
    name: 'spy', version: '1.0.0', description: 'test', spaceSettings: {},
    register(ctx) {
      seen = ctx;
      ctx.serve({ path: '/_fs/who', auth: 'token', handler: (req) => ({ json: { keys: Object.keys(req).sort() } }) });
      ctx.mcp.tool('spy_args', { description: 'test', inputSchema: { type: 'object', properties: {} }, perm: 'read' }, (a) => ({ keys: Object.keys(a).sort() }));
    },
  });
  const { t, admin } = await world(x, { enable: [], on: [], overrides: { plugins: [spy] } });
  await admin.post('/api/admin/plugins/spy', { enabled: true });
  await admin.post('/api/spaces/demo/plugins/spy', { enabled: true }, 'PUT');
  // Registered lazily at first use; trigger it with a document so the route has a token.
  const html = await (await admin.fetch('/s/demo/', { headers: DOC })).text();
  assert.ok(seen, 'register ran');
  for (const k of ['db', 'store', 'auth', 'cas', 'sessions']) assert.ok(!(k === 'cas' ? false : k in seen), `ctx.${k}`);
  assert.equal(typeof seen.cas.read, 'function');
  assert.equal(seen.cas.storeBuffer, undefined, 'no write-by-hash into the shared CAS beyond streaming');
  const flat = JSON.stringify(Object.keys(seen));
  assert.doesNotMatch(flat, /credential|session|csrf|secret|password/i);
  const tokenValue = /greenroom-doc-token" content="([^"]+)"/.exec(html);
  assert.equal(tokenValue, null, 'a plugin without the sqlite transform gets no doc token for free');
  // The route handler is handed the request data only, no credential and no db.
  const r = await fetch(t.base + '/s/demo/_fs/who', { headers: { 'sec-fetch-site': 'same-origin' } });
  assert.equal(r.status, 401, 'token routes need the doc token');
  // A tool handler gets the call's data, not core objects (the plugin's own ctx has the narrow CAS).
  assert.deepEqual(sc(await mcp(t, await token(admin, ['read']), 'spy_args', { slug: 'demo' })).keys, ['args', 'dir', 'settings', 'space']);
});

test('loader: cookies a plugin route sets are renamed and scoped to the space (rule 5)', async (x) => {
  const jar = definePlugin({
    name: 'jar', register(ctx) {
      ctx.serve({ path: '/_fs/jar', auth: 'none', handler: () => ({ json: {}, cookies: ['pref=dark; Path=/; Domain=evil.test; SameSite=Lax; Max-Age=60', 'fs_session=stolen', '__Host-x=1'], headers: { 'set-cookie': 'raw=1' } }) });
    },
  });
  const { t, admin } = await world(x, { enable: [], on: [], overrides: { plugins: [jar] } });
  await admin.post('/api/admin/plugins/jar', { enabled: true });
  await admin.post('/api/spaces/demo/plugins/jar', { enabled: true }, 'PUT');
  await admin.post('/api/spaces/demo', { privacy: 'public' }, 'PATCH');
  const r = await fetch(t.base + '/s/demo/_fs/jar');
  assert.equal(r.status, 200);
  const sp = t.store.space('demo');
  assert.deepEqual(r.headers.getSetCookie(), [`fsp_${sp.id.slice(4, 12)}_pref=dark; Path=/s/demo/; Secure; SameSite=None; Max-Age=60`]);
});

test('loader: a space that lists a plugin this instance lacks keeps its data and says so', async (x) => {
  const { t, admin } = await world(x, { enable: [], on: [] });
  t.db.prepare(`UPDATE spaces SET plugins_json = '["ghost"]'`).run();
  const list = await (await admin.fetch('/api/spaces/demo/plugins')).json();
  assert.ok(list.plugins.some((p) => p.name === 'ghost' && p.installed === false));
});

// ------------------------------------------------------------------ watermark

const link = async (admin, label) => (await (await admin.post('/api/spaces/demo/links', { label })).json()).link;
const asLink = async (t, l, p = '/') => { const c = client(t.base); const u = new URL(l.url); await c.fetch(u.pathname + u.search, { headers: DOC }); return c.fetch('/s/demo' + p, { headers: DOC }); };

test('watermark: shown only to share-link viewers, document views only', async (x) => {
  const { t, admin } = await world(x);
  const l = await link(admin, 'Acme Corp');
  const viaLink = await (await asLink(t, l)).text();
  assert.match(viaLink, /Confidential — prepared for Acme Corp/);
  assert.match(viaLink, /<\/div><\/body>/, 'before the last </body>');
  assert.doesNotMatch(await (await admin.fetch('/s/demo/', { headers: DOC })).text(), /Confidential/, 'team member');
  assert.equal((await (await asLink(t, l, '/a.css')).text()), 'x{}', 'subresources untouched');
  // public viewers
  await admin.post('/api/spaces/demo', { privacy: 'public' }, 'PATCH');
  assert.doesNotMatch(await (await client(t.base).fetch('/s/demo/', { headers: DOC })).text(), /Confidential/);
});

test('watermark: the 404 page gets the banner and the doc token too', async (x) => {
  const { t, admin } = await world(x);
  await admin.post('/api/spaces/demo/versions', { files: files({ 'index.html': PAGE, '404.html': PAGE }) });
  const r = await asLink(t, await link(admin, 'Acme'), '/missing');
  assert.equal(r.status, 404);
  const html = await r.text();
  assert.match(html, /Confidential — prepared for Acme/);
  assert.match(html, /greenroom-doc-token/);
});

test('watermark: off by default, and stored files never change', async (x) => {
  const { t, admin } = await world(x, { enable: ['watermark'], on: [] });
  const l = await link(admin, 'Acme');
  assert.doesNotMatch(await (await asLink(t, l)).text(), /Confidential/);
  await admin.post('/api/spaces/demo/plugins/watermark', { enabled: true }, 'PUT');
  assert.match(await (await asLink(t, l)).text(), /Confidential/);
  const sp = t.store.space('demo');
  const f = t.store.manifest(sp.live_version_id).find((m) => m.path === 'index.html');
  assert.equal(t.store.cas.size(f.sha256), PAGE.length);
});

test('watermark: the link label and the template are HTML-escaped', async (x) => {
  const { t, admin } = await world(x);
  await admin.post('/api/spaces/demo/plugins/watermark', { enabled: true, settings: { text: '<b>{client}</b> & co' } }, 'PUT');
  const l = await link(admin, '"><script>alert(1)</script>');
  const html = await (await asLink(t, l)).text();
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /&lt;b&gt;.*&lt;\/b&gt; &amp; co/);
});

// ------------------------------------------------------------------ sqlite

const docToken = async (c) => /greenroom-doc-token" content="([^"]+)"/.exec(await (await c.fetch('/s/demo/', { headers: DOC })).text())?.[1];
const api = (t, tok, body, method = 'POST') => fetch(t.base + '/s/demo/_fs/db', { method, headers: { 'content-type': 'application/json', ...(tok && { 'x-fs-doc-token': tok }) }, body: JSON.stringify(body) });

test('sqlite: MCP creates the database; the browser API obeys the per-table policy and the doc token', async (x) => {
  const { t, admin } = await world(x);
  const tok = await token(admin, ['publish', 'db', 'read']);
  assert.equal((await mcp(t, tok, 'db_exec', { slug: 'demo', sql: ['CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)', 'CREATE TABLE secrets (id INTEGER PRIMARY KEY, v TEXT)', "INSERT INTO secrets (v) VALUES ('x')"] })).status, 200);
  await admin.post('/api/spaces/demo/plugins/sqlite', { settings: { tables: { notes: 'read+insert' } } }, 'PUT');
  const dt = await docToken(admin);
  assert.ok(dt, 'documents get a doc token');

  assert.equal((await api(t, null, { op: 'tables' })).status, 401, 'no token');
  assert.equal((await api(t, 'bogus', { op: 'tables' })).status, 401);
  const tables = await (await api(t, dt, { op: 'tables' })).json();
  assert.deepEqual(tables.tables.map((x) => x.name), ['notes'], 'secrets is off, so invisible');
  assert.equal((await api(t, dt, { op: 'insert', table: 'notes', values: { body: 'hello' } })).status, 200);
  const rows = await (await api(t, dt, { op: 'select', table: 'notes' })).json();
  assert.equal(rows.rows[0].body, 'hello');
  assert.equal((await api(t, dt, { op: 'select', table: 'secrets' })).status, 404, 'an off table does not even admit it exists');
  assert.equal((await api(t, dt, { op: 'delete', table: 'notes', where: { id: 1 } })).status, 403, 'read+insert cannot delete');
  assert.equal((await api(t, dt, { op: 'select', table: 'notes; DROP TABLE notes' })).status >= 400, true, 'names are checked against the schema');
  assert.equal((await api(t, dt, { sql: 'select 1' })).status >= 400, true, 'no raw SQL from the browser');
  assert.equal((await api(t, dt, { op: 'select', table: 'notes', order: 'id' })).status, 400, 'order must be an array');
});

test('sqlite: the doc token is bound to the viewer, re-checked on every call', async (x) => {
  const { t, admin } = await world(x);
  const tok = await token(admin, ['publish', 'db', 'read']);
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: 'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)' });
  await admin.post('/api/spaces/demo/plugins/sqlite', { settings: { tables: { notes: 'read+write' } } }, 'PUT');
  const tables = (dt) => api(t, dt, { op: 'tables' }).then((r) => r.status);

  // a share-link viewer loses access the moment the link is revoked
  const l = await link(admin, 'Acme');
  const c = client(t.base);
  const u = new URL(l.url);
  await c.fetch(u.pathname + u.search, { headers: DOC });
  const lt = await docToken(c);
  assert.equal(await tables(lt), 200);
  await admin.post(`/api/spaces/demo/links/${l.id}/revoke`, {});
  assert.equal(await tables(lt), 401, 'revoked link');

  // ...and when the space goes team-only
  const l2 = await link(admin, 'Beta');
  const c2 = client(t.base);
  await c2.fetch(new URL(l2.url).pathname + new URL(l2.url).search, { headers: DOC });
  const lt2 = await docToken(c2);
  assert.equal(await tables(lt2), 200);
  await admin.post('/api/spaces/demo', { privacy: 'team' }, 'PATCH');
  assert.equal(await tables(lt2), 401, 'team-only now');

  // `none` routes answer only viewers of a non-public space
  assert.equal((await fetch(t.base + '/s/demo/_fs/db.js')).status, 401, 'anonymous on a team-only space');
  assert.equal((await admin.fetch('/s/demo/_fs/db.js')).status, 200, 'team member');

  // a team member's token dies with their session
  const tt = await docToken(admin);
  assert.equal(await tables(tt), 200);
  await admin.post('/api/logout', {});
  assert.equal(await tables(tt), 401, 'signed out');
});

test('sqlite: raw SQL over MCP needs the db scope, stays in this space file, and is guarded', async (x) => {
  const { t, admin } = await world(x);
  const rw = await token(admin, ['publish', 'db', 'read']);
  const noDb = await token(admin, ['publish', 'read']);
  assert.equal((await mcp(t, noDb, 'db_exec', { slug: 'demo', sql: 'CREATE TABLE a (x)' })).status, 403);
  await mcp(t, rw, 'db_exec', { slug: 'demo', sql: 'CREATE TABLE a (x)' });
  assert.equal(sc(await mcp(t, rw, 'db_query', { slug: 'demo', sql: 'SELECT count(*) AS n FROM a' })).rows[0].n, 0);
  for (const sql of ["ATTACH DATABASE '/etc/passwd' AS p", 'PRAGMA writable_schema = 1', 'VACUUM', 'DELETE FROM a; DROP TABLE a']) {
    const r = await mcp(t, rw, 'db_exec', { slug: 'demo', sql });
    assert.ok(r.status >= 400 || r.body.error || r.body.result?.isError, sql);
  }
  const w = await mcp(t, rw, 'db_query', { slug: 'demo', sql: 'DELETE FROM a' });
  assert.ok(w.status >= 400 || w.body.error || w.body.result?.isError, 'db_query is read-only');
  // the core tables are in another file
  const core = await mcp(t, rw, 'db_query', { slug: 'demo', sql: 'SELECT * FROM api_keys' });
  assert.ok(core.status >= 400 || core.body.error || core.body.result?.isError);
});

test('sqlite: results are capped in size and BLOBs come back as base64', async (x) => {
  const { t, admin } = await world(x);
  const tok = await token(admin, ['publish', 'db', 'read']);
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: ['CREATE TABLE b (id INTEGER PRIMARY KEY, v BLOB)', "INSERT INTO b (v) VALUES (x'00ff10')"] });
  assert.deepEqual(sc(await mcp(t, tok, 'db_query', { slug: 'demo', sql: 'SELECT v FROM b' })).rows, [{ v: { base64: 'AP8Q' } }]);
  await admin.post('/api/spaces/demo/plugins/sqlite', { settings: { tables: { b: 'read' } } }, 'PUT');
  assert.deepEqual((await (await api(t, await docToken(admin), { op: 'select', table: 'b' })).json()).rows, [{ id: 1, v: { base64: 'AP8Q' } }]);
  const huge = await mcp(t, tok, 'db_query', { slug: 'demo', sql: 'SELECT zeroblob(300000000)' });
  assert.ok(huge.status >= 400 || huge.body.error || huge.body.result?.isError, 'values above 8 MB fail');
  // many mid-size values: the response stops at 16 MB and says so
  const big = sc(await mcp(t, tok, 'db_query', { slug: 'demo', sql: 'WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n LIMIT 40) SELECT zeroblob(1000000) AS z FROM n' }));
  assert.equal(big.truncated, true);
  assert.ok(big.rows.length < 40);
});

test('sqlite: a plugin tool from a space without the plugin is not found', async (x) => {
  const { t, admin } = await world(x, { on: [] });
  const tok = await token(admin, ['publish', 'db', 'read']);
  const r = await mcp(t, tok, 'db_schema', { slug: 'demo' });
  assert.ok(r.status === 404 || r.body.error || r.body.result?.isError);
  assert.equal((await api(t, 'x', { op: 'tables' })).status, 405, 'the route is gone: a POST falls through to static hosting');
});

async function entries(file) {
  return withZip(file, {}, async ({ raw, open }) => {
    const out = new Map();
    for (const r of raw) { const parts = []; for await (const c of await open(r)) parts.push(c); out.set(r.name, Buffer.concat(parts)); }
    return out;
  });
}
const exportTo = async (admin, slug, history) => {
  const r = await admin.fetch(`/spaces/${slug}/export${history ? '?history=1' : ''}`);
  assert.equal(r.status, 200, await r.clone().text());
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fsx-')), 'b.zip');
  fs.writeFileSync(f, Buffer.from(await r.arrayBuffer()));
  return f;
};

/** Rebuild a bundle: `mutate(map, doc)` edits entries (name -> Buffer) and the parsed space.json. */
async function rezip(file, mutate) {
  const m = await entries(file);
  const doc = JSON.parse(m.get('space.json'));
  await mutate(m, doc);
  m.set('space.json', Buffer.from(JSON.stringify(doc)));
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fsx-')), 'r.zip');
  const w = new ZipWriter(out);
  for (const [k, v] of m) await w.add(k, v);
  await w.finish();
  return fs.readFileSync(out);
}
/** Make a zip's central directory claim `name` is `usize` bytes (a lying archive). */
function lie(buf, name, usize) {
  const at = buf.lastIndexOf(Buffer.from(name));
  buf.writeUInt32LE(usize, at - 46 + 24);
  return buf;
}
const importAs = (a, body, slug = 'copy') => a.fetch(`/api/import?slug=${slug}`, { method: 'POST', body, headers: { 'content-type': 'application/zip', 'x-csrf-token': a.csrf } });

test('import: plugin files count against the space size limit, installed or not', async (x) => {
  const { admin } = await world(x, { overrides: { maxSpaceBytes: 64 * 1024 } });
  const base = await exportTo(admin, 'demo', true);
  for (const plugin of ['ghost', 'sqlite']) {
    const zip = await rezip(base, (m, doc) => {
      doc.space.plugins = [plugin];
      m.set(`plugins/${plugin}/big.bin`, Buffer.alloc(1024 * 1024));
    });
    assert.equal((await importAs(admin, zip, 'big-' + plugin)).status, 413, plugin);
  }
  // An entry that inflates past its declared size is skipped.
  const lying = lie(await rezip(base, (m, doc) => {
    doc.space.plugins = ['ghost'];
    m.set('plugins/ghost/a.bin', Buffer.alloc(40 * 1024));
  }), 'plugins/ghost/a.bin', 10);
  const r = await importAs(admin, lying, 'liar');
  assert.equal(r.status, 201, await r.clone().text());
  assert.ok((await r.json()).warnings.some((w) => /ghost.*skipped|larger than its zip entry/.test(w)));
  // At most 100 snapshots come in.
  const many = await rezip(base, (m, doc) => {
    doc.space.plugins = ['sqlite'];
    for (let i = 0; i < 101; i++) m.set(`history/plugins/sqlite/snapshots/${crypto.createHash('sha256').update(String(i)).digest('hex')}.sqlite`, Buffer.from(String(i)));
  });
  const r2 = await importAs(admin, many, 'many');
  assert.equal(r2.status, 201, await r2.clone().text());
  assert.ok((await r2.json()).warnings.some((w) => /More than 100 snapshots/.test(w)));
});

test('sqlite: an imported database is checked, and its size cap follows its page size', async (x) => {
  const { t, admin } = await world(x);
  const base = await exportTo(admin, 'demo', false);
  const withDb = (buf) => rezip(base, (m) => { m.set('plugins/sqlite/app.sqlite', buf); });
  for (const [name, buf] of [['garbage', Buffer.from('not a database at all')], ['damaged', Buffer.concat([Buffer.from('SQLite format 3\0'), Buffer.alloc(4096, 7)])]]) {
    const r = await importAs(admin, await withDb(buf), name);
    assert.equal(r.status, 201, await r.clone().text());
    assert.ok((await r.json()).warnings.some((w) => /sqlite database was not imported/.test(w)), name);
  }
  // A 64 KiB-page database still stops at ~100 MB.
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'fsq-')), 'big.sqlite');
  const d = new DatabaseSync(f);
  d.exec('PRAGMA page_size = 65536; VACUUM; CREATE TABLE b (v BLOB)');
  d.close();
  assert.equal((await importAs(admin, await withDb(fs.readFileSync(f)), 'wide')).status, 201);
  const tok = (await (await admin.post('/api/tokens', { name: 'w', spaces: ['wide'], perms: ['db', 'read'] })).json()).token;
  const fill = await fetch(t.base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'db_exec', arguments: { slug: 'wide', sql: Array(14).fill('INSERT INTO b VALUES (zeroblob(8000000))') } } }) });
  const body = await fill.json();
  assert.match(JSON.stringify(body), /full/, 'full at 100 MB, not 1.6 GB');
});

test('sqlite: snapshots follow versions, and a database round-trips through both export zips', async (x) => {
  const { t, admin } = await world(x);
  await admin.post('/api/spaces/demo/plugins/sqlite', { settings: { snapshots: 'publish' } }, 'PUT');
  const tok = await token(admin, ['publish', 'db', 'read']);
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: ['CREATE TABLE n (v TEXT)', "INSERT INTO n VALUES ('one')"] });
  await admin.post('/api/spaces/demo/versions', { files: files({ 'index.html': PAGE }) });
  const list = sc(await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'list' }));
  assert.equal(list.snapshots.length, 1, 'publishing took a snapshot');
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: "UPDATE n SET v = 'two'" });
  assert.equal(sc(await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'restore', id: list.snapshots[0].id })).restored, list.snapshots[0].id);
  assert.equal(sc(await mcp(t, tok, 'db_query', { slug: 'demo', sql: 'SELECT v FROM n' })).rows[0].v, 'one');

  const cur = await entries(await exportTo(admin, 'demo', false));
  assert.ok([...cur.keys()].some((k) => /^plugins\/sqlite\/.*\.sqlite$/.test(k)), 'current zip carries the database');
  assert.ok(![...cur.keys()].some((k) => k.startsWith('history/')));
  const his = await entries(await exportTo(admin, 'demo', true));
  assert.ok([...his.keys()].some((k) => /^history\/plugins\/sqlite\//.test(k)), 'history zip carries the snapshots');
  assert.ok(his.has('plugins/sqlite/settings.json'));

  // Import it as a new space on a fresh instance with sqlite enabled.
  const t2 = await boot(); x.after(t2.close);
  const a2 = await setupAdmin(t2);
  await a2.post('/api/admin/plugins/sqlite', { enabled: true });
  const hz = fs.readFileSync(await exportTo(admin, 'demo', true));
  const up = await a2.fetch('/api/import?slug=copy', { method: 'POST', body: hz, headers: { 'content-type': 'application/zip', 'x-csrf-token': a2.csrf } });
  assert.equal(up.status, 201, await up.clone().text());
  assert.deepEqual(JSON.parse(t2.store.space('copy').plugins_json), ['sqlite', 'watermark']);
  const tok2 = (await (await a2.post('/api/tokens', { name: 'x', spaces: ['copy'], perms: ['db', 'read'] })).json()).token;
  const q = await (await fetch(t2.base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${tok2}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'db_query', arguments: { slug: 'copy', sql: 'SELECT v FROM n' } } }) })).json();
  assert.equal(q.result.structuredContent.rows[0].v, 'one');
});

test('sqlite: an import for a plugin this instance has not enabled keeps the files and re-exports them', async (x) => {
  const { t, admin } = await world(x);
  const tok = await token(admin, ['publish', 'db', 'read']);
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: ['CREATE TABLE n (v TEXT)', "INSERT INTO n VALUES ('kept')"] });
  const zip = fs.readFileSync(await exportTo(admin, 'demo', false));
  const t2 = await boot(); x.after(t2.close);
  const a2 = await setupAdmin(t2); // sqlite NOT enabled here
  const up = await a2.fetch('/api/import?slug=copy', { method: 'POST', body: zip, headers: { 'content-type': 'application/zip', 'x-csrf-token': a2.csrf } });
  assert.equal(up.status, 201, await up.clone().text());
  assert.ok((await up.json()).warnings.some((w) => /sqlite/.test(w)));
  const again = await entries(await exportTo(a2, 'copy', false));
  assert.deepEqual([...again.keys()].filter((k) => k.startsWith('plugins/sqlite/')).sort(), [...(await entries(await exportTo(admin, 'demo', false))).keys()].filter((k) => k.startsWith('plugins/sqlite/')).sort());
});

test('sqlite: restore picks a snapshot by id even when versions repeat', async (x) => {
  const { t, admin } = await world(x);
  await admin.post('/api/spaces/demo/plugins/sqlite', { settings: { snapshots: 'manual' } }, 'PUT');
  const tok = await token(admin, ['publish', 'db', 'read']);
  const q = async () => sc(await mcp(t, tok, 'db_query', { slug: 'demo', sql: 'SELECT v FROM n' })).rows[0].v;
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: ['CREATE TABLE n (v TEXT)', "INSERT INTO n VALUES ('a')"] });
  const a = sc(await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'create' })).snapshot;
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: "UPDATE n SET v = 'b'" });
  const b = sc(await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'create' })).snapshot;
  assert.equal(a.version, b.version);
  await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'restore', id: a.id });
  assert.equal(await q(), 'a');
  await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'restore', id: b.id });
  assert.equal(await q(), 'b');
});

test('sqlite: snapshots round-trip while the plugin is switched off', async (x) => {
  const { t, admin } = await world(x);
  await admin.post('/api/spaces/demo/plugins/sqlite', { settings: { snapshots: 'manual' } }, 'PUT');
  const tok = await token(admin, ['publish', 'db', 'read']);
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: 'CREATE TABLE n (v TEXT)' });
  const { snapshot } = sc(await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'create' }));
  await admin.post('/api/admin/plugins/sqlite', { enabled: false });
  const zip = await exportTo(admin, 'demo', true);
  const keys = [...(await entries(zip)).keys()];
  assert.ok(keys.includes(`history/plugins/sqlite/snapshots/${snapshot.sha256}.sqlite`), 'the CAS blob is exported');
  assert.ok(keys.includes('history/plugins/sqlite/snapshots.json'));
  assert.ok(!keys.some((k) => k.startsWith('plugins/sqlite/history/')));
  // into an instance where sqlite is installed but off, then switched on
  const t2 = await boot(); x.after(t2.close);
  const a2 = await setupAdmin(t2);
  assert.equal((await importAs(a2, fs.readFileSync(zip))).status, 201);
  await a2.post('/api/admin/plugins/sqlite', { enabled: true });
  const tok2 = (await (await a2.post('/api/tokens', { name: 'x', spaces: ['copy'], perms: ['db', 'read'] })).json()).token;
  const list = await (await fetch(t2.base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${tok2}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'db_checkpoint', arguments: { slug: 'copy', action: 'list' } } }) })).json();
  assert.equal(list.result.structuredContent.snapshots[0].sha256, snapshot.sha256);
});

test('sqlite: snapshot blobs survive garbage collection', async (x) => {
  const { t, admin } = await world(x);
  await admin.post('/api/spaces/demo/plugins/sqlite', { settings: { snapshots: 'manual' } }, 'PUT');
  const tok = await token(admin, ['publish', 'db', 'read']);
  await mcp(t, tok, 'db_exec', { slug: 'demo', sql: 'CREATE TABLE n (v TEXT)' });
  await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'create' });
  const [snap] = sc(await mcp(t, tok, 'db_checkpoint', { slug: 'demo', action: 'list' })).snapshots;
  t.db.prepare("DELETE FROM meta WHERE key = 'last_gc'").run();
  await t.store.maybeGc(true);
  assert.notEqual(t.store.cas.size(snap.sha256), null);
});

test('export activity is logged', async (x) => {
  const { t, admin } = await world(x);
  await exportTo(admin, 'demo', false);
  assert.ok(t.db.prepare("SELECT 1 FROM activity_log WHERE action = 'space.exported'").get());
});

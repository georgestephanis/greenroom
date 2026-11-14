import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { boot, client, setupAdmin } from './helpers.js';
import { makeZip } from './zipbuilder.js';
import { importZip } from '../src/zip.js';
import { CAS } from '../src/cas.js';
import { hashPassword, verifyPassword, normaliseScope, can } from '../src/auth.js';
import { sha256hex } from '../src/util.js';
import { parseRedirectsFile } from '../src/routing.js';

const f = (o) => Object.entries(o).map(([path, content]) => ({ path, content }));
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'fs-test-'));

test('CAS: dedupes, verifies hash, gc keeps active blobs after the grace period', async () => {
  const d = tmp();
  const cas = new CAS(path.join(d, 'b'), path.join(d, 't'));
  const a = await cas.storeBuffer(Buffer.from('hello'));
  assert.equal(a.sha256, sha256hex('hello'));
  assert.equal(a.sha256, (await cas.storeBuffer(Buffer.from('hello'))).sha256);
  assert.ok(cas.path(a.sha256).includes(`${path.sep}${a.sha256.slice(0, 2)}${path.sep}`));
  const b = await cas.storeBuffer(Buffer.from('bye'));
  const r = await cas.gc(new Set([a.sha256]), -1);
  assert.equal(r.removed, 1);
  assert.ok(cas.has(a.sha256) && !cas.has(b.sha256));
  await assert.rejects(cas.storeStream((async function* () { yield Buffer.alloc(50); })(), 10));
});

test('versions: patch publish, diff, rollback creates a new version, history is immutable', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await setupAdmin(t);
  await admin.post('/api/spaces', { name: 'Site', slug: 'site' });
  const v1 = await (await admin.post('/api/spaces/site/versions', { files: f({ 'index.html': 'one', 'a.txt': 'a' }) })).json();
  const v2 = await (await admin.post('/api/spaces/site/versions', { base: 'live', files: f({ 'index.html': 'two', 'b.txt': 'b' }), remove: ['a.txt'] })).json();
  assert.equal(v1.version.number, 1); assert.equal(v2.version.number, 2);
  const d = await (await admin.fetch('/api/spaces/site/diff?from=1&to=2')).json();
  assert.deepEqual([d.added.map((x) => x.path), d.removed.map((x) => x.path), d.changed.map((x) => x.path)], [['b.txt'], ['a.txt'], ['index.html']]);
  const rb = await (await admin.post('/api/spaces/site/rollback', { version: 1 })).json();
  assert.equal(rb.version.number, 3);
  assert.equal(rb.version.message, 'Rollback to v1');
  const pub = await (await admin.fetch('/api/spaces/site')).json();
  assert.equal(pub.space.live_version_id, rb.version.id);
  assert.equal(t.store.manifest(t.store.version(t.store.space('site').id, 2).id).length, 2); // v2 untouched
  assert.equal((await admin.post('/api/spaces/site/versions', { files: [{ path: '../evil', content: 'x' }] })).status, 400);
  assert.equal((await admin.post('/api/spaces/site/versions', { base: 99, files: [] })).status, 404);
});

test('zip import: strips shared folder, rejects traversal, duplicate paths and bombs', async () => {
  const d = tmp();
  const cas = new CAS(path.join(d, 'b'), path.join(d, 't'));
  const lim = { maxFileBytes: 1000, maxTotalBytes: 5000 };
  const write = (buf) => { const p = path.join(d, `${Math.random()}.zip`); fs.writeFileSync(p, buf); return p; };
  const ok = await importZip(write(makeZip([{ name: 'site/index.html', data: '<h1>', deflate: true }, { name: 'site/css/a.css', data: 'x' }, { name: '__MACOSX/x', data: '' }])), cas, lim);
  assert.deepEqual([...ok.keys()].sort(), ['css/a.css', 'index.html']);
  await assert.rejects(importZip(write(makeZip([{ name: '../evil', data: 'x' }])), cas, lim), /Unsafe path/);
  await assert.rejects(importZip(write(makeZip([{ name: 'ok', data: 'y' }, { name: 'a/../../evil', data: 'x' }])), cas, lim), /Unsafe path/);
  await assert.rejects(importZip(write(makeZip([{ name: 'a', data: 'x' }, { name: 'a', data: 'y' }])), cas, lim), /Duplicate/);
  // declares 10 bytes, actually inflates to 1 MB: bounded by the real size
  await assert.rejects(importZip(write(makeZip([{ name: 'bomb', data: Buffer.alloc(1 << 20), deflate: true, lieSize: 10 }])), cas, lim), /Could not store/);
  await assert.rejects(importZip(write(Buffer.from('not a zip')), cas, lim), /Not a zip/);
});

test('upload endpoint publishes a zip as a new version', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await setupAdmin(t);
  await admin.post('/api/spaces', { name: 'Z', slug: 'z' });
  const r = await admin.fetch('/api/spaces/z/upload?message=hi', { method: 'POST', body: makeZip([{ name: 'index.html', data: 'zipped' }]), headers: { 'x-csrf-token': admin.csrf, 'content-type': 'application/zip' } });
  assert.equal(r.status, 201, await r.clone().text());
  const anon = client(t.base);
  await admin.post('/api/spaces/z', { privacy: 'public' }, 'PATCH');
  assert.equal(await (await anon.fetch('/s/z/')).text(), 'zipped');
  const noCsrf = await admin.fetch('/api/spaces/z/upload', { method: 'POST', body: makeZip([]) });
  assert.equal(noCsrf.status, 403);
});

test('serving: clean urls, directory redirect, redirects file, 404 page, range, etag', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await setupAdmin(t);
  await admin.post('/api/spaces', { name: 'S', slug: 's' });
  await admin.post('/api/spaces/s/versions', { files: f({ 'index.html': 'home', 'about.html': 'about', 'docs/index.html': 'docs', '404.html': 'lost', '_redirects': '/old /about.html 301\n/app/* /index.html 200\n', 'data.bin': '0123456789' }) });
  await admin.post('/api/spaces/s', { privacy: 'public' }, 'PATCH');
  const c = client(t.base);
  const get = (p, h) => c.fetch(p, { headers: h });
  assert.equal(await (await get('/s/s/about')).text(), 'about');
  assert.equal((await get('/s/s/docs')).headers.get('location'), '/s/s/docs/');
  assert.equal(await (await get('/s/s/docs/')).text(), 'docs');
  const old = await get('/s/s/old');
  assert.equal(old.status, 301); assert.equal(old.headers.get('location'), '/s/s/about.html');
  assert.equal(await (await get('/s/s/app/deep/link')).text(), 'home');
  const nf = await get('/s/s/nope');
  assert.equal(nf.status, 404); assert.equal(await nf.text(), 'lost');
  assert.equal((await get('/s/s/_redirects')).status, 404);
  const r = await get('/s/s/data.bin', { range: 'bytes=2-4' });
  assert.equal(r.status, 206); assert.equal(await r.text(), '234');
  const e = (await get('/s/s/data.bin')).headers.get('etag');
  assert.equal((await get('/s/s/data.bin', { 'if-none-match': e })).status, 304);
  assert.equal((await get('/s/s/a%2f..%2fb')).status, 400);
});

test('auth: scrypt PHC hashes, invites, login throttle, disabled users', async (x) => {
  const h = await hashPassword('hunter2hunter2');
  assert.match(h, /^\$scrypt\$/);
  assert.ok(await verifyPassword('hunter2hunter2', h));
  assert.ok(!(await verifyPassword('nope', h)));
  const t = await boot(); x.after(t.close);
  const admin = await setupAdmin(t);
  assert.equal((await client(t.base).json('/api/setup', { email: 'b@example.com', password: 'longenoughpass' })).status, 403);
  const inv = await (await admin.post('/api/invites', { role: 'member' })).json();
  const token = inv.invite.split('/invite/')[1];
  const bob = client(t.base);
  assert.equal((await bob.json('/api/invites/accept', { token, email: 'bob@example.com', password: 'bobs-long-password', name: 'Bob' })).status, 201);
  assert.equal((await client(t.base).json('/api/invites/accept', { token, email: 'eve@example.com', password: 'bobs-long-password' })).status, 400); // single use
  bob.csrf = t.db.prepare("SELECT csrf_token FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = 'bob@example.com'").get().csrf_token;
  const bobPost = (p, b) => bob.json(p, b, 'POST', { 'x-csrf-token': bob.csrf });
  assert.equal((await bobPost('/api/invites', {})).status, 403); // members cannot invite
  const bobUser = t.db.prepare("SELECT id FROM users WHERE username = 'bob@example.com'").get().id;
  assert.equal((await admin.post(`/api/users/${bobUser}/disable`, {})).status, 200);
  assert.equal((await bob.fetch('/api/me')).status, 401); // disabled => session dead
  assert.equal((await client(t.base).json('/api/login', { email: 'bob@example.com', password: 'bobs-long-password' })).status, 401);
  const attacker = client(t.base);
  let last;
  for (let i = 0; i < 11; i++) last = await attacker.json('/api/login', { email: 'ada@example.com', password: 'wrong' + i });
  assert.equal(last.status, 429);
});

test('credentials: scopes fail closed; escalation needs a session; granter is live', async (x) => {
  assert.equal(normaliseScope({ spaces: '*', create: true, perms: ['publish', 'telepathy'], readOnly: false }), null);
  assert.equal(normaliseScope('garbage'), null);
  const sc = normaliseScope({ spaces: ['a'], create: false, perms: ['publish', 'read'], readOnly: false });
  const cred = { scope: sc };
  assert.ok(can(cred, 'publish', 'a') && !can(cred, 'publish', 'b') && !can(cred, 'create'));
  assert.ok(!can({ scope: { ...sc, readOnly: true } }, 'publish', 'a'));

  const t = await boot(); x.after(t.close);
  const admin = await setupAdmin(t);
  await admin.post('/api/spaces', { name: 'A', slug: 'a' });
  await admin.post('/api/spaces', { name: 'B', slug: 'b' });
  const uid = t.db.prepare('SELECT id FROM users').get().id;
  const token = 'fsa_' + 'k'.repeat(40);
  t.db.prepare("INSERT INTO api_keys (id,user_id,name,key_hash,token_prefix,created_at,kind,scope_json) VALUES ('key_1',?,?,?,?,?,?,?)")
    .run(uid, 'agent', sha256hex(token), token.slice(0, 12), new Date().toISOString(), 'agent_token', JSON.stringify({ spaces: ['a'], create: false, perms: ['publish', 'read'], readOnly: false }));
  const agent = (p, body, method = 'POST') => fetch(t.base + p, { method, body: body && JSON.stringify(body), headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' } });
  assert.equal((await agent('/api/spaces/a/versions', { files: f({ 'index.html': 'hi' }) })).status, 201);
  assert.equal((await agent('/api/spaces/b/versions', { files: f({ 'index.html': 'hi' }) })).status, 404);
  assert.equal((await agent('/api/spaces', { name: 'New' })).status, 403);
  assert.equal((await agent('/api/spaces/a', { privacy: 'public' }, 'PATCH')).status, 403); // escalation
  assert.equal((await agent('/api/invites', {})).status, 403);
  assert.equal((await agent('/api/admin/gc', {})).status, 403);
  const v = t.store.versions(t.store.space('a').id)[0];
  assert.match(v.author_name, /^agent \(via Ada\)$|^Agent \(via Ada\)$/);
  t.db.prepare('UPDATE users SET disabled_at = ?').run('2020-01-01T00:00:00Z'); // granter removed => credential dies
  assert.equal((await agent('/api/spaces/a/versions', { files: f({ 'x': 'y' }) })).status, 401);
});

test('lazy GC: runs at most per interval, force runs now, referenced blobs survive', async (x) => {
  const t = await boot({ gcIntervalHours: 12 }); x.after(t.close);
  const admin = await setupAdmin(t);
  await admin.post('/api/spaces', { name: 'G', slug: 'g' });
  await admin.post('/api/spaces/g/versions', { files: f({ 'index.html': 'keep' }) });
  const orphan = await t.store.cas.storeBuffer(Buffer.from('orphan'));
  fs.utimesSync(t.store.cas.path(orphan.sha256), new Date(0), new Date(0));
  assert.equal(t.store.maybeGc(), null); // interval not elapsed (publish already ran one)
  const r = await (await admin.post('/api/admin/gc', {})).json();
  assert.equal(r.removed, 1);
  assert.ok(!t.store.cas.has(orphan.sha256));
  assert.ok(t.store.cas.has(sha256hex('keep')));
});

test('routing: redirects parser keeps working', () => {
  const r = parseRedirectsFile('/a /b 301\n');
  assert.equal(r.rules[0].status, 301);
});

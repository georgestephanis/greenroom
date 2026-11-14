// M4: portable export/import, history.fi, hostile bundles (issue #214 section 8).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { boot, setupAdmin } from './helpers.js';
import { withZip } from '../src/zip.js';
import { signExport } from '../src/bundle.js';
import { makeZip } from './zipbuilder.js';
import { historyEntries, currentEntries, sha } from './bundlebuilder.js';

const FIX = new URL('./fixtures/bundles/', import.meta.url).pathname;
const tmp = (x) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'fsb-')); x.after(() => fs.rmSync(d, { recursive: true, force: true })); return d; };

/** name -> Buffer for every entry of a zip on disk. */
async function readAll(file) {
  return withZip(file, {}, async ({ raw, open }) => {
    const out = new Map();
    for (const r of raw) { const parts = []; for await (const c of await open(r)) parts.push(c); out.set(r.name, Buffer.concat(parts)); }
    return out;
  });
}
const toZip = (entries) => makeZip(entries.map((e) => ({ name: e.name, data: e.data ?? '' })));

async function world(x, overrides) {
  const t = await boot(overrides); x.after(t.close);
  const admin = await setupAdmin(t);
  return { t, admin };
}
const imp = (admin, body, q = '') => admin.fetch('/api/import' + q, { method: 'POST', body, headers: { 'content-type': 'application/zip', 'x-csrf-token': admin.csrf } });
const download = async (x, admin, p) => {
  const r = await admin.fetch(p);
  assert.equal(r.status, 200);
  const f = path.join(tmp(x), 'out.zip');
  fs.writeFileSync(f, Buffer.from(await r.arrayBuffer()));
  return f;
};

/** alpha: 3 versions (one by an agent token), an empty file, an awkward path, redirects, and a password-protected share link. */
async function seeded(x) {
  const w = await world(x);
  const { admin, t } = w;
  await admin.post('/api/spaces', { name: 'Alpha', slug: 'alpha' });
  await admin.post('/api/spaces/alpha/versions', { message: 'First', files: [{ path: 'index.html', content: '<h1>1</h1>' }, { path: 'a.css', content: 'x{}' }, { path: '_redirects', content: '/old /index.html 301\n' }, { path: 'empty.txt', content: '' }] });
  const minted = await (await admin.post('/api/tokens', { name: 'Claude', spaces: ['alpha'], perms: ['publish', 'read', 'export'] })).json();
  const agent = (p, body) => fetch(t.base + p, { method: 'POST', headers: { authorization: `Bearer ${minted.token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await agent('/api/spaces/alpha/versions', { message: 'Agent edit', base: 'live', files: [{ path: 'index.html', content: '<h1>2</h1>' }, { path: 'my "dir"/ñ file.txt', content: 'hi' }] })).status, 201);
  await admin.post('/api/spaces/alpha/versions', { message: 'Drop css', base: 'live', remove: ['a.css'], files: [{ path: 'b.js', content: 'let b' }] });
  const link = await (await admin.post('/api/spaces/alpha/links', { label: 'Acme', password: 'hunter2-secret' })).json();
  return { ...w, minted, link: link.link };
}

function snapshot(t, slug, { ids = true } = {}) {
  const sp = t.store.space(slug);
  return {
    live: ids ? sp.live_version_id : t.store.versions(sp.id).find((v) => v.id === sp.live_version_id).number,
    versions: t.store.versions(sp.id).reverse().map((v) => ({
      number: v.number, ...(ids && { id: v.id, parent: v.parent_version_id }), author: v.author_name, message: v.message, source: v.source,
      created_at: v.created_at, routing: v.routing_json, warnings: v.warnings_json,
      files: t.store.manifest(v.id).map((f) => [f.path, f.sha256, f.size, f.content_type]).sort((a, b) => (a[0] < b[0] ? -1 : 1)),
    })),
  };
}

test('current export has space.json and site/ only, and nothing secret', async (x) => {
  const { admin, link, minted } = await seeded(x);
  const names = [...(await readAll(await download(x, admin, '/spaces/alpha/export'))).keys()].sort();
  assert.deepEqual(names, ['site/_redirects', 'site/b.js', 'site/empty.txt', 'site/index.html', 'site/my "dir"/ñ file.txt', 'space.json']);
  const all = await readAll(await download(x, admin, '/spaces/alpha/export?history=1'));
  assert.ok(['history/versions.json', 'history/history.fi', 'activity.json', 'space.json'].every((n) => all.has(n)));
  const blob = Buffer.concat([...all.values()]).toString('latin1');
  for (const secret of [link.url.split('key=')[1], 'hunter2-secret', minted.token, minted.token.slice(0, 12)]) assert.ok(!blob.includes(secret), 'secret leaked');
  assert.ok(!/secret_hash|password_hash|key_hash|scrypt|raw_token/i.test(blob));
  const doc = JSON.parse(all.get('space.json'));
  assert.equal(doc.format, 'freespace-bundle/1');
  assert.equal(doc.kind, 'history');
});

test('round trip into a fresh instance gives identical manifests and history', async (x) => {
  const a = await seeded(x);
  const file = await download(x, a.admin, '/spaces/alpha/export?history=1');
  const b = await world(x);
  const r = await imp(b.admin, fs.readFileSync(file));
  assert.equal(r.status, 201, await r.clone().text());
  const j = await r.json();
  assert.equal(j.space.slug, 'alpha');
  assert.equal(j.versions, 3);
  assert.deepEqual(snapshot(b.t, 'alpha'), snapshot(a.t, 'alpha'));
  assert.equal(b.t.store.space('alpha').id, a.t.store.space('alpha').id, 'ids are preserved');
  assert.equal(b.t.store.space('alpha').owner_id, b.t.db.prepare('SELECT id FROM users').get().id, 'the importer owns it');
  assert.equal(b.t.db.prepare('SELECT COUNT(*) c FROM grants').get()?.c ?? 0, 0, 'no links come along');
  // The live site serves.
  assert.equal(await (await b.admin.fetch('/s/alpha/', { headers: { 'sec-fetch-dest': 'document' } })).text(), '<h1>2</h1>');
  // Exporting the import again reproduces the history parts byte for byte.
  const again = await readAll(await download(x, b.admin, '/spaces/alpha/export?history=1'));
  const orig = await readAll(file);
  for (const n of orig.keys()) if (!['space.json', 'activity.json'].includes(n)) assert.ok(orig.get(n).equals(again.get(n)), n);
  assert.deepEqual([...again.keys()].sort(), [...orig.keys()].sort());
});

test('importing next to the original remaps ids; a taken slug is refused unless replacing', async (x) => {
  const { t, admin, link } = await seeded(x);
  const file = await download(x, admin, '/spaces/alpha/export?history=1');
  const body = fs.readFileSync(file);
  assert.equal((await imp(admin, body)).status, 409);
  const r = await imp(admin, body, '?slug=alpha-copy');
  assert.equal(r.status, 201, await r.clone().text());
  const j = await r.json();
  assert.equal(j.remapped, true);
  assert.ok(j.warnings.some((w) => /already exists here/.test(w)));
  const [a, c] = [t.store.space('alpha'), t.store.space('alpha-copy')];
  assert.notEqual(a.id, c.id);
  assert.equal(t.db.prepare('SELECT COUNT(DISTINCT id) c FROM versions').get().c, 6);
  assert.deepEqual(snapshot(t, 'alpha-copy', { ids: false }), snapshot(t, 'alpha', { ids: false }));
  assert.equal(c.live_version_id, t.store.versions(c.id).find((v) => v.number === 3).id);
  // Replace: same slug, versions swapped, links kept.
  const before = t.db.prepare('SELECT COUNT(*) c FROM activity_log WHERE space_id = ?').get(a.id).c;
  const rep = await imp(admin, body, '?replace=1');
  assert.equal(rep.status, 201, await rep.clone().text());
  assert.equal(t.store.space('alpha').id, a.id);
  assert.equal(t.store.links(t.store.space('alpha')).length, 1, 'share links survive a replace');
  assert.ok(t.db.prepare('SELECT COUNT(*) c FROM activity_log WHERE space_id = ?').get(a.id).c > before, 'activity is appended, not replaced');
  assert.equal(link.id, t.store.links(t.store.space('alpha'))[0].id);
});

test('replace and import are for people, not agent credentials', async (x) => {
  const { t, admin, minted } = await seeded(x);
  const body = fs.readFileSync(await download(x, admin, '/spaces/alpha/export'));
  const r = await fetch(t.base + '/api/import?replace=1', { method: 'POST', body, headers: { authorization: `Bearer ${minted.token}`, 'content-type': 'application/zip' } });
  assert.equal(r.status, 403);
  assert.equal(t.db.prepare('SELECT COUNT(*) c FROM spaces').get().c, 1);
});

test('a current bundle imports its site as one version', async (x) => {
  const { t, admin } = await world(x);
  const r = await imp(admin, fs.readFileSync(FIX + 'current.freespace.zip'));
  assert.equal(r.status, 201, await r.clone().text());
  const j = await r.json();
  assert.equal(j.versions, 1);
  assert.ok(j.warnings.some((w) => /sqlite/.test(w)), 'plugin data is called out, not silently dropped');
  const sp = t.store.space('current-fixture');
  assert.equal(sp.privacy, 'public');
  assert.equal(sp.noindex, 0);
  const files = t.store.manifest(sp.live_version_id);
  assert.deepEqual(files.map((f) => [f.path, f.size]).sort(), [['empty.txt', 0], ['index.html', 20]]);
  assert.equal(t.store.versions(sp.id)[0].author_name, 'Claude (via Ada)');
});

test('committed fixture bundles import and keep their history', async (x) => {
  const { t, admin } = await world(x);
  const r = await imp(admin, fs.readFileSync(FIX + 'history.freespace-history.zip'));
  assert.equal(r.status, 201, await r.clone().text());
  const sp = t.store.space('fixture');
  assert.equal(sp.id, 'spc_fix');
  assert.equal(sp.live_version_id, 'ver_fix2');
  assert.deepEqual(t.store.versions(sp.id).map((v) => [v.number, v.id, v.parent_version_id, v.author_name, v.created_at]),
    [[2, 'ver_fix2', 'ver_fix1', 'Claude (via Ada)', '2025-03-02T10:00:00.000Z'], [1, 'ver_fix1', null, 'Ada', '2025-03-01T10:00:00.000Z']]);
  assert.equal(t.db.prepare('SELECT COUNT(*) c FROM activity_log WHERE space_id = ? AND action = ?').get('spc_fix', 'version.created').c, 1);
});

function fastImport(x, historyFi) {
  const repo = path.join(tmp(x), 'r.git');
  assert.equal(spawnSync('git', ['init', '-q', '--bare', repo]).status, 0);
  const r = spawnSync('git', ['--git-dir', repo, 'fast-import', '--quiet'], { input: historyFi, encoding: 'buffer', maxBuffer: 1 << 28 });
  assert.equal(r.status, 0, r.stderr.toString());
  const git = (...a) => { const o = spawnSync('git', ['--git-dir', repo, ...a], { encoding: 'utf8' }); assert.equal(o.status, 0, o.stderr); return o.stdout; };
  git('fsck', '--strict');
  return git;
}

test('history.fi loads with git fast-import: one commit per version, agents named, files match', async (x) => {
  const { t, admin } = await seeded(x);
  const fi = (await readAll(await download(x, admin, '/spaces/alpha/export?history=1'))).get('history/history.fi');
  const git = fastImport(x, fi);
  const log = git('log', '--reverse', '--format=%an%x09%at%x09%s', 'main').trim().split('\n').map((l) => l.split('\t'));
  const vs = t.store.versions(t.store.space('alpha').id).reverse();
  assert.deepEqual(log.map((l) => [l[0], l[2]]), vs.map((v) => [v.author_name, v.message]));
  assert.deepEqual(log.map((l) => Number(l[1])), vs.map((v) => Math.floor(Date.parse(v.created_at) / 1000)));
  assert.ok(log.some((l) => l[0] === 'Claude (via Ada)'));
  for (const [i, v] of vs.entries()) {
    const tree = git('ls-tree', '-r', '-z', '--name-only', `main~${vs.length - 1 - i}`).split('\0').filter(Boolean).sort();
    assert.deepEqual(tree, t.store.manifest(v.id).map((f) => f.path).sort(), `tree of v${v.number}`);
  }
  assert.match(git('log', '-1', '--format=%B', 'main'), /Freespace-Version: ver_/);
});

test('a history that restarts from a new root still fast-imports', async (x) => {
  const { admin } = await world(x);
  assert.equal((await imp(admin, fs.readFileSync(FIX + 'restart.freespace-history.zip'))).status, 201);
  const fi = (await readAll(await download(x, admin, '/spaces/fixture/export?history=1'))).get('history/history.fi');
  const git = fastImport(x, fi);
  assert.equal(git('rev-list', '--count', 'main').trim(), '3');
  assert.equal(git('ls-tree', '-r', '--name-only', 'main').trim(), 'index.html', 'the restart commit does not inherit earlier files');
});

test('a branched history (publish with base:N) keeps every version reachable from main', async (x) => {
  const { admin } = await world(x);
  await admin.post('/api/spaces', { name: 'B', slug: 'b' });
  const pub = (body) => admin.post('/api/spaces/b/versions', body);
  await pub({ message: 'v1', files: [{ path: 'a.txt', content: '1' }] });
  await pub({ message: 'v2', base: 'live', files: [{ path: 'b.txt', content: '2' }] });
  await pub({ message: 'v3', base: 1, files: [{ path: 'c.txt', content: '3' }] }); // branches off v1
  await pub({ message: 'v4', base: 'live', files: [{ path: 'd.txt', content: '4' }] });
  const fi = (await readAll(await download(x, admin, '/spaces/b/export?history=1'))).get('history/history.fi');
  const git = fastImport(x, fi);
  assert.deepEqual(git('log', '--reverse', '--format=%s', 'main').trim().split('\n'), ['v1', 'v2', 'v3', 'v4']);
  assert.match(git('log', '--format=%B', '--grep=v3', 'main'), /Freespace-Parent: ver_/);
  assert.deepEqual(git('ls-tree', '-r', '--name-only', 'main~1').trim().split('\n'), ['a.txt', 'c.txt']);
});

test('a space with a .git path still exports a loadable stream', async (x) => {
  const { admin } = await world(x);
  await admin.post('/api/spaces', { name: 'G', slug: 'g' });
  const r = await admin.post('/api/spaces/g/versions', { files: [{ path: 'index.html', content: 'x' }, { path: 'sub/.git/config', content: '[core]' }] });
  assert.equal(r.status, 201, 'the store accepts the path; git cannot hold it');
  const fi = (await readAll(await download(x, admin, '/spaces/g/export?history=1'))).get('history/history.fi');
  assert.equal(fastImport(x, fi)('ls-tree', '-r', '--name-only', 'main').trim(), 'index.html');
});

test('MCP export_space returns a signed link that works once signed and not otherwise', async (x) => {
  const { t, minted } = await seeded(x);
  const call = async (token, args) => {
    const r = await fetch(t.base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'export_space', arguments: args } }) });
    return { status: r.status, body: await r.json() };
  };
  const ok = await call(minted.token, { slug: 'alpha', history: true });
  assert.equal(ok.status, 200);
  const u = new URL(ok.body.result.structuredContent.url);
  assert.match(u.pathname, /^\/export\/spc_[\w-]+\/history$/);
  const got = await fetch(t.base + u.pathname + u.search);
  assert.equal(got.status, 200);
  assert.equal(got.headers.get('content-type'), 'application/zip');
  assert.match(got.headers.get('content-disposition'), /alpha\.freespace-history\.zip/);
  assert.equal(Buffer.from(await got.arrayBuffer()).subarray(0, 2).toString(), 'PK');
  const tampered = new URL(u); tampered.searchParams.set('sig', '0'.repeat(64));
  assert.equal((await fetch(t.base + tampered.pathname + tampered.search)).status, 404);
  const swapped = await fetch(t.base + u.pathname.replace('history', 'current') + u.search);
  assert.equal(swapped.status, 404, 'a link for one export cannot fetch the other');
  const sid = t.store.space('alpha').id;
  const old = signExport(t.config.secret, sid, u.searchParams.get('c'), false, -5);
  assert.equal((await fetch(t.base + old.path)).status, 404, 'expired');
  const other = new URL(u); other.searchParams.set('c', 'key_other');
  assert.equal((await fetch(t.base + other.pathname + other.search)).status, 404, 'bound to the credential that asked');
  // The link dies with its credential, and with its space.
  t.db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ?').run('2020-01-01T00:00:00.000Z', u.searchParams.get('c'));
  assert.equal((await fetch(t.base + u.pathname + u.search)).status, 404, 'revoked credential');
});

test('export_space needs the export scope', async (x) => {
  const { t, admin } = await seeded(x);
  const m = await (await admin.post('/api/tokens', { name: 'ro', spaces: ['alpha'], perms: ['read'] })).json();
  const r = await fetch(t.base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${m.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'export_space', arguments: { slug: 'alpha' } } }) });
  assert.equal(r.status, 403);
  assert.match(r.headers.get('www-authenticate'), /insufficient_scope/);
});

// ------------------------------------------------------------------ hostile bundles

const HOSTILE = {
  'not a zip': () => Buffer.from('definitely not a zip'),
  'no space.json': () => toZip(historyEntries(({ entries }) => entries.splice(0, 1))),
  'unknown format': () => toZip(historyEntries(({ doc }) => { doc.format = 'freespace-bundle/9'; })),
  'bad kind': () => toZip(historyEntries(({ doc }) => { doc.kind = 'weird'; })),
  'history kind without versions': () => toZip(historyEntries(({ doc, entries }) => { doc.kind = 'history'; entries.splice(1, 1); })),
  'space.json not json': () => makeZip([{ name: 'space.json', data: '{nope' }]),
  'path traversal in zip': () => toZip(historyEntries(({ entries }) => entries.push({ name: 'site/../../evil', data: 'x' }))),
  'absolute path in zip': () => toZip(historyEntries(({ entries }) => entries.push({ name: '/etc/passwd', data: 'x' }))),
  'non-canonical path in zip': () => toZip(historyEntries(({ entries }) => entries.push({ name: 'site//x', data: 'x' }))),
  'duplicate zip entry': () => toZip(historyEntries(({ entries }) => entries.push({ ...entries[2] }))),
  'traversal path in manifest': () => toZip(historyEntries(({ versions }) => { versions[0].files[0].path = '../escape.html'; })),
  'absolute path in manifest': () => toZip(historyEntries(({ versions }) => { versions[0].files[0].path = '/abs.html'; })),
  'duplicate path in manifest': () => toZip(historyEntries(({ versions }) => versions[0].files.push({ ...versions[0].files[0] }))),
  'bad sha in manifest': () => toZip(historyEntries(({ versions }) => { versions[0].files[0].sha256 = 'ZZ'; })),
  'missing blob': () => toZip(historyEntries(({ entries }) => entries.splice(2, 1))),
  'blob does not match its hash': () => toZip(historyEntries(({ entries }) => { entries[2].data = 'tampered contents'; })),
  'manifest size lies': () => toZip(historyEntries(({ versions }) => { versions[0].files[0].size = 3; })),
  'bad version id': () => toZip(historyEntries(({ versions }) => { versions[0].id = 'ver_../../x'; })),
  'bad space id': () => toZip(historyEntries(({ doc }) => { doc.space.id = 'nope'; })),
  'parent from the future': () => toZip(historyEntries(({ versions }) => { versions[0].parent = 'ver_fix2'; })),
  'unknown parent': () => toZip(historyEntries(({ versions }) => { versions[1].parent = 'ver_ghost'; })),
  'duplicate version number': () => toZip(historyEntries(({ versions }) => { versions[1].number = 1; })),
  'live version not in history': () => toZip(historyEntries(({ doc }) => { doc.space.live_version_id = 'ver_ghost'; })),
  'bad timestamp': () => toZip(historyEntries(({ versions }) => { versions[0].created_at = 'yesterday'; })),
  'bad privacy': () => toZip(historyEntries(({ doc }) => { doc.space.privacy = 'everyone'; })),
  'bad slug': () => toZip(historyEntries(({ doc }) => { doc.space.slug = '../x'; })),
  'huge name': () => toZip(historyEntries(({ doc }) => { doc.space.name = 'x'.repeat(5000); })),
  'declared size is a lie (zip bomb)': () => makeZip(historyEntries(({ entries, versions }) => {
    const big = Buffer.alloc(3 << 20, 0);
    versions[0].files[0] = { path: 'index.html', sha256: sha(big), size: 10, type: 'text/html' };
    entries.push({ name: `history/blobs/${sha(big).slice(0, 2)}/${sha(big)}`, data: big, deflate: true, lieSize: 10 });
  }).map((e) => ({ ...e, data: e.data ?? '' }))),
  'site/ without any files': () => toZip(currentEntries(({ entries }) => entries.splice(1, 2))),
};

for (const [name, build] of Object.entries(HOSTILE)) {
  test(`hostile bundle: ${name}`, async (x) => {
    const { t, admin } = await world(x);
    const r = await imp(admin, build());
    assert.ok([400, 413].includes(r.status), `${name}: got ${r.status} ${await r.clone().text()}`);
    assert.equal(t.db.prepare('SELECT COUNT(*) c FROM spaces').get().c, 0, 'nothing was created');
    assert.equal(t.db.prepare('SELECT COUNT(*) c FROM versions').get().c, 0);
  });
}

test('the valid control bundle imports (so the hostile cases fail for their own reasons)', async (x) => {
  const { admin } = await world(x);
  assert.equal((await imp(admin, toZip(historyEntries()))).status, 201);
});

test('a bundle bigger than the space limit is refused as 413, before storing anything', async (x) => {
  const { t, admin } = await world(x, { maxSpaceBytes: 20 });
  const r = await imp(admin, toZip(historyEntries()));
  assert.equal(r.status, 413);
  assert.equal(t.db.prepare('SELECT COUNT(*) c FROM spaces').get().c, 0);
});

test('importing needs a session and a CSRF token', async (x) => {
  const { t, admin } = await world(x);
  const body = toZip(historyEntries());
  assert.equal((await fetch(t.base + '/api/import', { method: 'POST', body, headers: { 'content-type': 'application/zip' } })).status, 403);
  assert.equal((await admin.fetch('/api/import', { method: 'POST', body, headers: { 'content-type': 'application/zip' } })).status, 403, 'no CSRF header');
  assert.equal(t.db.prepare('SELECT COUNT(*) c FROM spaces').get().c, 0);
});

test('a space export bigger than the upload cap still imports (import has its own cap)', async (x) => {
  const { admin } = await seeded(x);
  const file = await download(x, admin, '/spaces/alpha/export?history=1');
  const body = fs.readFileSync(file);
  const { t: small, admin: a2 } = await world(x, { maxUploadBytes: body.length - 1 });
  assert.equal((await imp(a2, body)).status, 201);
  assert.equal(small.store.space('alpha').slug, 'alpha');
  const { admin: a3 } = await world(x, { maxUploadBytes: body.length - 1, maxImportBytes: body.length - 1 });
  assert.equal((await imp(a3, body)).status, 413, 'the import cap still applies');
});

test('a taken slug is refused before any blob is stored', async (x) => {
  const { t, admin } = await seeded(x);
  const count = (d) => fs.readdirSync(d, { withFileTypes: true }).reduce((n, e) => n + (e.isDirectory() ? count(path.join(d, e.name)) : 1), 0);
  const n = count(t.store.cas.baseDir);
  const bundle = toZip(historyEntries(({ doc, blobs }) => { doc.space.slug = 'alpha'; blobs.index = Buffer.from('never stored'); }));
  assert.equal((await imp(admin, bundle)).status, 409);
  assert.equal(count(t.store.cas.baseDir), n);
});

test('a failed replace leaves the old versions and live pointer untouched', async (x) => {
  const { t, admin } = await seeded(x);
  const sp = t.store.space('alpha');
  const before = JSON.stringify(snapshot(t, 'alpha'));
  const bad = toZip(historyEntries(({ doc, entries }) => { doc.space.slug = 'alpha'; entries[2].data = 'tampered blob'; })); // a blob that no longer matches its hash, after earlier blobs were stored
  const r = await imp(admin, bad, '?replace=1');
  assert.ok([400, 413].includes(r.status), String(r.status));
  assert.equal(JSON.stringify(snapshot(t, 'alpha')), before);
  assert.equal(t.store.space('alpha').live_version_id, sp.live_version_id);
});

test('filenames that look like Finder litter survive a bundle round trip; imported activity is marked', async (x) => {
  const { admin } = await world(x);
  await admin.post('/api/spaces', { name: 'D', slug: 'd' });
  await admin.post('/api/spaces/d/versions', { files: [{ path: 'index.html', content: 'x' }, { path: 'foo.DS_Store', content: 'keep me' }] });
  const { t, admin: a2 } = await world(x);
  assert.equal((await imp(a2, fs.readFileSync(await download(x, admin, '/spaces/d/export?history=1')))).status, 201);
  assert.deepEqual(t.store.manifest(t.store.space('d').live_version_id).map((f) => f.path).sort(), ['foo.DS_Store', 'index.html']);
  assert.ok(t.db.prepare('SELECT detail_json FROM activity_log WHERE space_id = ?').all(t.store.space('d').id).some((a) => JSON.parse(a.detail_json).imported));
});

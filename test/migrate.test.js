// Move to Spacefast against a fake Spacefast API on a local HTTPS server (same test CA as ssrf.test.js).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import crypto from 'node:crypto';
import { boot, client, setupAdmin } from './helpers.js';

const fx = (f) => fs.readFileSync(new URL(`./fixtures/${f}`, import.meta.url));
const tls = { ca: fx('cimd-test.crt'), lookup: (h, o, cb) => (o?.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4)) };
const f = (o) => Object.entries(o).map(([path, content]) => ({ path, content }));
const TOKEN = 'sfk_test_secret_123';

// Hands out one upload target per page, API-relative, so the refresh loop has to run.
async function fakeSpacefast(t, { privateOnly = false, taken = [] } = {}) {
  const log = { spaces: [], versions: [], finalize: [], blobs: new Map(), auth: new Set() };
  const pending = new Map();
  const page = (sid, vid) => {
    const left = pending.get(vid);
    if (!left.length) return { versionId: vid };
    const file = left.shift();
    return { versionId: vid, upload: { targets: [{ path: file.path, method: 'PUT', url: `/v1/spaces/${sid}/blobs/${file.sha256}`, headers: { 'x-upload-token': 'sfu_1' } }],
      links: { refresh: `/v1/spaces/${sid}/versions/${vid}/uploads/refresh` } } };
  };
  const s = https.createServer({ key: fx('cimd-test.key'), cert: fx('cimd-test.crt') }, async (q, r) => {
    const chunks = []; for await (const c of q) chunks.push(c);
    const raw = Buffer.concat(chunks), isJson = q.headers['content-type'] === 'application/json';
    if (isJson && !raw.length) return r.writeHead(400).end('{"detail":"empty JSON body"}'); // like the real API
    const body = isJson ? JSON.parse(raw) : {};
    log.auth.add(q.headers.authorization);
    const send = (code, data) => { r.writeHead(code, { 'content-type': 'application/json' }); r.end(JSON.stringify(data)); };
    const p = q.url.split('/').slice(1);
    if (q.url === '/v1/spaces') {
      if (taken.includes(body.slug)) return send(409, { title: 'Conflict', detail: 'slug is taken', code: 'slug_taken' });
      if (privateOnly && body.access === 'public') return send(403, { detail: 'private only', code: 'team_private_spaces_only' });
      log.spaces.push(body);
      return send(201, { data: { space: { id: `sp_${body.slug}`, url: `https://${body.slug}.spacefast.example/` } } });
    }
    if (p[3] === 'versions' && !p[4]) {
      const vid = `v${log.versions.length + 1}`;
      log.versions.push({ sid: p[2], ...body });
      pending.set(vid, [...body.files]);
      return send(201, { data: page(p[2], vid) });
    }
    if (p[5] === 'uploads') return send(200, { data: page(p[2], p[4]) });
    if (p[3] === 'blobs') {
      assert.equal(q.headers['x-upload-token'], 'sfu_1');
      assert.equal(crypto.createHash('sha256').update(raw).digest('hex'), p[4]);
      log.blobs.set(p[4], raw.toString());
      return send(200, {});
    }
    if (p[5] === 'finalize') { log.finalize.push({ vid: p[4], body, key: q.headers['idempotency-key'] }); return send(200, { data: { status: 'ready' } }); }
    send(404, { detail: 'nope' });
  });
  await new Promise((res) => s.listen(0, '127.0.0.1', res));
  t.after(() => { s.closeAllConnections(); s.close(); });
  return { log, url: `https://cimd.test:${s.address().port}/v1` };
}

async function finished(admin) {
  for (;;) {
    const { migration } = await (await admin.fetch('/api/admin/migrate')).json();
    if (migration.done) return migration;
    await new Promise((r) => setTimeout(r, 20));
  }
}

test('moves spaces with history: oldest first, only the live version goes live, bytes match', async (t) => {
  const app = await boot({ outboundTls: tls });
  t.after(app.close);
  const sf = await fakeSpacefast(t);
  const admin = await setupAdmin(app);
  await admin.post('/api/spaces', { name: 'Site', slug: 'site' });
  await admin.post('/api/spaces/site/versions', { files: f({ 'index.html': 'one' }), message: 'first' });
  await admin.post('/api/spaces/site/versions', { files: f({ 'index.html': 'two', 'a.css': 'b{}' }), message: 'second' });
  await admin.post('/api/spaces/site/rollback', { version: 1 }); // v3 is live, same bytes as v1
  await admin.post('/api/spaces/site', { privacy: 'public' }, 'PATCH');
  await admin.post('/api/spaces', { name: 'Empty', slug: 'empty' });

  const start = await admin.post('/api/admin/migrate', { url: sf.url, token: TOKEN, spaces: ['site', 'empty'], history: true });
  assert.equal(start.status, 202);
  assert.ok(!(await start.text()).includes(TOKEN));
  assert.equal((await admin.post('/api/admin/migrate', { url: sf.url, token: TOKEN, spaces: ['site'] })).status, 409);
  const job = await finished(admin);

  assert.ok(!JSON.stringify(job).includes(TOKEN));
  assert.deepEqual(job.spaces.map((s) => [s.slug, s.status, s.versions]), [['site', 'done', 3], ['empty', 'skipped', 0]]);
  assert.deepEqual(sf.log.spaces, [{ slug: 'site', title: 'Site', access: 'public' }]);
  assert.deepEqual(sf.log.versions.slice(0, 2).map((v) => v.source.message), ['first', 'second']);
  assert.equal(sf.log.versions[0].source.kind, 'import');
  assert.match(sf.log.versions[0].source.client, /^greenroom\//);
  assert.deepEqual(sf.log.finalize.map((x) => x.body), [{ channel: null }, { channel: null }, {}]);
  assert.deepEqual([...sf.log.blobs.values()].sort(), ['b{}', 'one', 'two']);
  assert.deepEqual([...sf.log.auth], [`Bearer ${TOKEN}`]); // same-origin uploads carry the key; nothing went without it
  assert.equal(job.spaces[0].url, 'https://site.spacefast.example/');
});

test('live only by default; private-only teams, taken slugs and private addresses are reported per space', async (t) => {
  const app = await boot({ outboundTls: tls });
  t.after(app.close);
  const sf = await fakeSpacefast(t, { privateOnly: true, taken: ['taken'] });
  const admin = await setupAdmin(app);
  for (const slug of ['pub', 'taken']) {
    await admin.post('/api/spaces', { name: slug, slug });
    await admin.post(`/api/spaces/${slug}/versions`, { files: f({ 'index.html': slug }) });
    await admin.post(`/api/spaces/${slug}/versions`, { files: f({ 'index.html': `${slug}2` }) });
  }
  await admin.post('/api/spaces/pub', { privacy: 'public' }, 'PATCH');
  await admin.post('/api/admin/migrate', { url: sf.url, token: TOKEN, spaces: ['pub', 'taken'] });
  const job = await finished(admin);
  assert.deepEqual(job.spaces.map((s) => [s.slug, s.status, s.versions]), [['pub', 'done', 1], ['taken', 'failed', 0]]);
  assert.match(job.spaces[0].note, /private/);
  assert.match(job.spaces[1].note, /slug is taken/);
  assert.deepEqual(sf.log.spaces, [{ slug: 'pub', title: 'pub', access: 'private' }]);
  assert.deepEqual(sf.log.finalize.map((x) => x.body), [{}]);

  // Without the test CA override the SSRF guard applies: a private address never gets the token.
  const real = await boot();
  t.after(real.close);
  const a2 = await setupAdmin(real);
  await a2.post('/api/spaces', { name: 'S', slug: 's' });
  await a2.post('/api/spaces/s/versions', { files: f({ 'index.html': 'x' }) });
  await a2.post('/api/admin/migrate', { url: 'https://127.0.0.1:9/', token: TOKEN, spaces: ['s'] });
  const j2 = await finished(a2);
  assert.equal(j2.spaces[0].status, 'failed');
  assert.match(j2.spaces[0].note, /Blocked private address/);
});

test('admins only; bad input is refused before anything starts', async (t) => {
  const app = await boot({ outboundTls: tls });
  t.after(app.close);
  const admin = await setupAdmin(app);
  await admin.post('/api/spaces', { name: 'S', slug: 's' });
  assert.equal((await admin.post('/api/admin/migrate', { url: 'http://api.spacefast.com', token: TOKEN, spaces: ['s'] })).status, 400);
  assert.equal((await admin.post('/api/admin/migrate', { url: 'https://api.spacefast.com', token: '', spaces: ['s'] })).status, 400);
  assert.equal((await admin.post('/api/admin/migrate', { url: 'https://api.spacefast.com', token: TOKEN, spaces: [] })).status, 400);
  assert.equal((await client(app.base).json('/api/admin/migrate', { url: 'https://api.spacefast.com', token: TOKEN, spaces: ['s'] })).status, 401);
  const page = await (await admin.fetch('/instance/migrate')).text();
  assert.match(page, /name="token" autocomplete="off"/);
});

// Gaps closed in the feedback batch: password reset links, role changes, invite revocation, space rename and delete.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { boot, client, setupAdmin } from './helpers.js';

const invite = async (admin, app, role = 'member') => {
  const { invite } = await (await admin.post('/api/invites', { role })).json();
  const bob = client(app.base);
  assert.equal((await bob.json('/api/invites/accept', { token: invite.split('/').pop(), name: 'Bob', email: 'bob@example.com', password: 'bob password 123' })).status, 201);
  return { bob, id: app.db.prepare("SELECT id FROM users WHERE username = 'bob@example.com'").get().id };
};

test('an admin reset link sets a new password once and signs the person out everywhere', async (t) => {
  const app = await boot();
  t.after(app.close);
  const admin = await setupAdmin(app);
  const { bob, id } = await invite(admin, app);

  const first = (await (await admin.post(`/api/users/${id}/reset`, {})).json()).link;
  const { link } = await (await admin.post(`/api/users/${id}/reset`, {})).json();
  const token = link.split('/reset/')[1];
  assert.equal((await client(app.base).json('/api/reset', { token: first.split('/reset/')[1], password: 'never used 123' })).status, 400); // superseded
  assert.match(await (await fetch(`${app.base}/reset/${token}`)).text(), /Choose a new password/);
  assert.equal((await client(app.base).json('/api/reset', { token, password: 'short' })).status, 400);
  assert.equal((await client(app.base).json('/api/reset', { token, password: 'bob new password' })).status, 200); // a short try didn't spend it
  assert.equal((await client(app.base).json('/api/reset', { token, password: 'again again 123' })).status, 400); // single use
  assert.equal((await bob.fetch('/api/me')).status, 401);
  assert.equal((await client(app.base).json('/api/login', { email: 'bob@example.com', password: 'bob new password' })).status, 200);

  const member = client(app.base);
  await member.json('/api/login', { email: 'bob@example.com', password: 'bob new password' });
  const html = await (await member.fetch('/')).text();
  const csrf = /name="csrf" content="([^"]+)"/.exec(html)[1];
  const r = await member.fetch(`/api/users/${id}/reset`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': csrf }, body: '{}' });
  assert.equal(r.status, 403); // members can't mint them
});

test('the CLI prints a working reset link', async (t) => {
  const app = await boot();
  t.after(app.close);
  await setupAdmin(app);
  const out = execFileSync(process.execPath, ['bin/greenroom.js', 'reset-link', 'ada@example.com'], { env: { ...process.env, GREENROOM_DATA_DIR: app.config.dataDir, GREENROOM_PUBLIC_URL: app.base } }).toString();
  const token = /\/reset\/([\w-]+)/.exec(out)[1];
  assert.equal((await client(app.base).json('/api/reset', { token, password: 'recovered pass 1' })).status, 200);
  assert.equal((await client(app.base).json('/api/login', { email: 'ada@example.com', password: 'recovered pass 1' })).status, 200);
});

test('roles change, but never away from the last active admin; invites can be revoked', async (t) => {
  const app = await boot();
  t.after(app.close);
  const admin = await setupAdmin(app);
  const ada = app.db.prepare("SELECT id FROM users WHERE username = 'ada@example.com'").get().id;
  assert.equal((await admin.post(`/api/users/${ada}/role`, { role: 'member' })).status, 400);
  const { id } = await invite(admin, app);
  assert.equal((await admin.post(`/api/users/${id}/role`, { role: 'admin' })).status, 200);
  assert.equal((await admin.post(`/api/users/${ada}/role`, { role: 'member' })).status, 200); // Bob is an admin now
  assert.equal(app.db.prepare('SELECT role FROM users WHERE id = ?').get(ada).role, 'member');

  const app2 = await boot();
  t.after(app2.close);
  const a2 = await setupAdmin(app2);
  const { invite: link } = await (await a2.post('/api/invites', { role: 'member' })).json();
  assert.match(await (await a2.fetch('/team')).text(), /Open invites/);
  const inv = app2.db.prepare('SELECT id FROM invites').get().id;
  assert.equal((await a2.post(`/api/invites/${inv}/revoke`, {})).status, 200);
  assert.equal((await client(app2.base).json('/api/invites/accept', { token: link.split('/').pop(), name: 'Eve', email: 'eve@example.com', password: 'eve password 123' })).status, 400);
});

test('a space can be renamed, moved to a new slug from the form, and deleted', async (t) => {
  const app = await boot();
  t.after(app.close);
  const admin = await setupAdmin(app);
  await admin.post('/api/spaces', { name: 'Draft', slug: 'draft' });
  const form = (path, body) => admin.fetch(path, { method: 'POST', body: new URLSearchParams({ _csrf: admin.csrf, ...body }).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded', referer: `${app.base}/spaces/draft` } });
  const r = await form('/api/spaces/draft', { _method: 'PATCH', name: 'Final', slug: 'final' });
  assert.equal(r.headers.get('location'), '/spaces/final');
  assert.match(await (await admin.fetch('/spaces/final')).text(), /<h1>Final<\/h1>/);
  assert.equal((await form('/api/spaces/final', { _method: 'DELETE' })).headers.get('location'), '/');
  assert.equal((await admin.fetch('/spaces/final')).status, 404);
});

test('Restore from the history form goes back to the space page', async (t) => {
  const app = await boot();
  t.after(app.close);
  const admin = await setupAdmin(app);
  await admin.post('/api/spaces', { name: 'Site', slug: 'site' });
  const f = (s) => [{ path: 'index.html', content: s }];
  for (const s of ['one', 'two']) assert.equal((await admin.post('/api/spaces/site/versions', { files: f(s) })).status, 201);
  const r = await admin.fetch('/api/spaces/site/rollback', { method: 'POST', body: new URLSearchParams({ _csrf: admin.csrf, version: '1', _next: '/spaces/site' }).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded', referer: `${app.base}/spaces/site` } });
  assert.equal(r.headers.get('location'), '/spaces/site');
  assert.match(await (await admin.fetch('/spaces/site')).text(), /Rollback to v1/);
});

test('the slug field pattern is valid in browsers (v flag) and agrees with the server', async (t) => {
  const app = await boot();
  t.after(app.close);
  const admin = await setupAdmin(app);
  await admin.post('/api/spaces', { name: 'Site', slug: 'site' });
  const html = await (await admin.fetch('/spaces/site')).text();
  const pattern = /<input name="slug"[^>]* pattern="([^"]+)"/.exec(html)[1].replace(/&#\d+;/g, (e) => String.fromCharCode(e.slice(2, -1)));
  const browser = new RegExp(`^(?:${pattern})$`, 'v'); // how browsers compile the pattern attribute
  const { SLUG_RE } = await import('../src/util.js');
  for (const s of ['a', 'site', 'q3-board-report', 'a'.repeat(62), 'a'.repeat(63), 'Bad', '-x', 'x-', 'a_b', '']) assert.equal(browser.test(s), SLUG_RE.test(s), s);
});

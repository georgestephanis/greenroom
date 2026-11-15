// A person's own account page: display name and password.
import test from 'node:test';
import assert from 'node:assert/strict';
import { boot, client, setupAdmin } from './helpers.js';

test('a person renames themselves; agent tokens cannot', async (t) => {
  const app = await boot();
  t.after(app.close);
  const admin = await setupAdmin(app);
  assert.equal((await admin.post('/api/account', { name: '  Ada   Lovelace ' })).status, 200);
  assert.match(await (await admin.fetch('/')).text(), /<a href="\/account">Ada Lovelace<\/a>/);
  assert.equal((await admin.post('/api/account', { name: '   ' })).status, 400);
  assert.equal((await admin.post('/api/account', { name: 'x'.repeat(101) })).status, 400);

  const { token } = await (await admin.post('/api/tokens', { name: 'bot', perms: ['publish'] })).json();
  const bot = await fetch(`${app.base}/api/account`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: '{"name":"Bot"}' });
  assert.equal(bot.status, 403);
  assert.equal(app.db.prepare('SELECT display_name FROM users').get().display_name, 'Ada Lovelace');

  // Form posts land back on the page, with the error shown there.
  const form = (body) => admin.fetch('/api/account', { method: 'POST', body: new URLSearchParams({ _csrf: admin.csrf, ...body }).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded', referer: `${app.base}/account` } });
  assert.equal((await form({ name: 'Ada' })).headers.get('location'), '/account?saved=name');
  const bad = (await form({ name: '' })).headers.get('location');
  assert.match(bad, /^\/account\?error=/);
  assert.match(await (await admin.fetch(bad)).text(), /Name must be 1 to 100 characters/);
});

test('changing the password needs the current one and signs out other sessions', async (t) => {
  const app = await boot();
  t.after(app.close);
  const admin = await setupAdmin(app);
  const other = client(app.base);
  assert.equal((await other.json('/api/login', { email: 'ada@example.com', password: 'correct horse battery' })).status, 200);

  assert.equal((await admin.post('/api/account/password', { current: 'wrong password!', password: 'new password 123' })).status, 400);
  assert.equal((await admin.post('/api/account/password', { current: 'correct horse battery', password: 'short' })).status, 400);
  assert.equal((await admin.post('/api/account/password', { current: 'correct horse battery', password: 'new password 123' })).status, 200);

  assert.equal((await admin.fetch('/api/me')).status, 200); // this session stays
  assert.equal((await other.fetch('/api/me')).status, 401); // the other one is gone
  assert.equal((await client(app.base).json('/api/login', { email: 'ada@example.com', password: 'correct horse battery' })).status, 401);
  assert.equal((await client(app.base).json('/api/login', { email: 'ada@example.com', password: 'new password 123' })).status, 200);
});

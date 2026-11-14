// M3: share links, passwords, expiry, view tracking, branding (issue #214 section 6).
import test from 'node:test';
import assert from 'node:assert/strict';
import { boot, client, setupAdmin } from './helpers.js';
import fs from 'node:fs';
import os from 'node:os';
import nodePath from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { viewerCookieName, SPACE_CSP } from '../src/security.js';
import { MIGRATIONS, openDb } from '../src/db.js';
import { sha256hex } from '../src/util.js';

const DOC = { 'sec-fetch-dest': 'document' };
const files = { files: [{ path: 'index.html', content: '<h1>hi</h1>' }, { path: 'a.css', content: 'x{}' }] };

async function world(x, overrides) {
  const t = await boot(overrides); x.after(t.close);
  const admin = await setupAdmin(t);
  for (const slug of ['alpha', 'beta']) {
    await admin.post('/api/spaces', { name: slug, slug });
    await admin.post(`/api/spaces/${slug}/versions`, files);
  }
  const link = async (slug, body = {}) => {
    const r = await admin.post(`/api/spaces/${slug}/links`, body);
    assert.equal(r.status, 201, await r.clone().text());
    return (await r.json()).link;
  };
  const space = (slug) => t.db.prepare('SELECT * FROM spaces WHERE slug = ?').get(slug);
  return { t, admin, link, space };
}
const path = (u) => { const x = new URL(u); return x.pathname + x.search; };

test('?key= sets a space+link cookie and redirects to the URL without the key', async (x) => {
  const { t, link, space } = await world(x);
  const l = await link('alpha', { label: 'Acme' });
  assert.equal(space('alpha').privacy, 'link', 'creating a link switches a team space to link');
  const v = client(t.base);
  const r = await v.fetch(path(l.url).replace('?', '?x=1&'), { headers: DOC });
  assert.equal(r.status, 303);
  assert.equal(r.headers.get('location'), '/s/alpha/?x=1');
  assert.equal(r.headers.get('content-security-policy'), SPACE_CSP);
  const sc = r.headers.get('set-cookie');
  assert.match(sc, new RegExp(`^${viewerCookieName(space('alpha'))}=`));
  assert.match(sc, /Path=\/s\/alpha\/; HttpOnly; Secure; SameSite=None; Max-Age=259(2000|1999)$/);
  assert.equal((await v.fetch('/s/alpha/', { headers: DOC })).status, 200);
  assert.equal((await v.fetch('/s/alpha/a.css')).status, 200, 'subresources load with the cookie');
  // Unknown key, and no key at all, get nothing.
  assert.equal((await client(t.base).fetch('/s/alpha/?key=sfl_nope', { headers: DOC })).status, 410);
  assert.equal((await client(t.base).fetch('/s/alpha/a.css')).status, 401);
});

test('a cookie for space A is rejected on space B, and a key for A does not open B', async (x) => {
  const { t, link, space } = await world(x);
  const l = await link('alpha');
  await link('beta');
  const v = client(t.base);
  await v.fetch(path(l.url));
  const value = v.jar.get(viewerCookieName(space('alpha')));
  assert.ok(value);
  const r = await fetch(`${t.base}/s/beta/a.css`, { headers: { cookie: `${viewerCookieName(space('beta'))}=${value}` } });
  assert.equal(r.status, 401);
  assert.equal((await client(t.base).fetch(`/s/beta/?key=${new URL(l.url).searchParams.get('key')}`)).status, 410);
});

test('revocation and expiry take effect on the next request', async (x) => {
  const { t, admin, link } = await world(x);
  const l = await link('alpha');
  const v = client(t.base);
  await v.fetch(path(l.url));
  assert.equal((await v.fetch('/s/alpha/a.css')).status, 200);
  assert.equal((await admin.post(`/api/spaces/alpha/links/${l.id}/revoke`, {})).status, 200);
  assert.equal((await v.fetch('/s/alpha/a.css')).status, 401);
  assert.equal((await v.fetch('/s/alpha/', { headers: DOC })).status, 410);
  assert.equal((await client(t.base).fetch(path(l.url))).status, 410);

  const e = await link('alpha', { expires_at: new Date(Date.now() + 3600e3).toISOString() });
  const w = client(t.base);
  const r = await w.fetch(path(e.url));
  assert.ok(Number(/Max-Age=(\d+)/.exec(r.headers.get('set-cookie'))[1]) <= 3600, 'cookie lives no longer than the link');
  assert.equal((await w.fetch('/s/alpha/a.css')).status, 200);
  t.db.prepare('UPDATE grants SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), e.id);
  assert.equal((await w.fetch('/s/alpha/a.css')).status, 401);
  assert.equal((await admin.post('/api/spaces/alpha/links', { expires_at: '2001-01-01' })).status, 400);
});

test('max uses are spent per cookie issued, not per view; previews and HEAD spend nothing', async (x) => {
  const { t, admin, link } = await world(x);
  const l = await link('alpha', { max_uses: 2 });
  const a = client(t.base), b = client(t.base);
  // An unfurler (GET or HEAD, no cookie kept) sees the Open page and spends nothing.
  assert.equal((await client(t.base).fetch(path(l.url), { method: 'HEAD' })).status, 200);
  const preview = await client(t.base).fetch(path(l.url), { headers: DOC });
  assert.equal(preview.status, 200);
  assert.equal(preview.headers.get('set-cookie'), null);
  assert.match(await preview.text(), /<form method="post">.*<button>Open<\/button>/);
  const open = (c) => c.fetch(path(l.url), { method: 'POST' });
  assert.equal((await open(a)).status, 303);
  assert.equal((await open(a)).status, 303, 'revisiting with the key while holding the cookie is free');
  assert.equal((await a.fetch(path(l.url))).status, 303, 'so is a GET once in');
  for (let i = 0; i < 3; i++) assert.equal((await a.fetch('/s/alpha/', { headers: DOC })).status, 200);
  assert.equal((await open(b)).status, 303);
  assert.equal((await open(client(t.base))).status, 410, 'third browser is refused');
  assert.equal((await a.fetch('/s/alpha/a.css')).status, 200, 'existing holders keep access');
  const [row] = (await (await admin.fetch('/api/spaces/alpha/links')).json()).links;
  assert.equal(row.uses, 2);
  assert.equal(row.view_count, 3, 'document views counted, subresources not');
  assert.ok(row.first_viewed_at && row.last_viewed_at);
  // Unlimited links still open straight from GET; HEAD sets no cookie there either.
  const u = await link('alpha');
  const head = await client(t.base).fetch(path(u.url), { method: 'HEAD' });
  assert.equal(head.headers.get('set-cookie'), null);
  assert.equal((await client(t.base).fetch(path(u.url))).status, 303);
  assert.equal(t.db.prepare('SELECT uses_count FROM grants WHERE id = ?').get(u.id).uses_count, 1);
});

test('password links: form, wrong password, brute-force throttle per link and IP', async (x) => {
  const { t, link } = await world(x, { trustProxy: true });
  const l = await link('alpha', { password: 'opensesame' });
  const kind = t.db.prepare('SELECT kind FROM grants WHERE id = ?').get(l.id).kind;
  assert.equal(kind, 'password', 'a link with a password is a password grant');
  const v = client(t.base);
  const get = await v.fetch(path(l.url), { headers: DOC });
  assert.equal(get.status, 200);
  assert.match(await get.text(), /type="password"/);
  assert.equal(get.headers.get('set-cookie'), null);
  const tryPw = (password, ip = '203.0.113.1') => v.fetch(path(l.url), {
    method: 'POST', body: new URLSearchParams({ password }).toString(),
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': `10.0.0.1, ${ip}` },
  });
  assert.equal((await tryPw('nope')).status, 401);
  for (let i = 0; i < 9; i++) await tryPw('nope');
  const blocked = await tryPw('opensesame');
  assert.equal(blocked.status, 429, 'even the right password is refused once throttled');
  assert.equal(blocked.headers.get('content-security-policy'), SPACE_CSP);
  const xs = (h) => v.fetch(path(l.url), { method: 'POST', body: 'password=opensesame', headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': '203.0.113.3', ...h } });
  assert.equal((await xs({ origin: 'https://evil.example' })).status, 403, 'foreign Origin');
  assert.equal((await xs({ 'sec-fetch-site': 'cross-site' })).status, 403, 'cross-site without Origin');
  assert.equal((await xs({ 'sec-fetch-site': 'cross-site', origin: 'null' })).status, 303, 'our own sandboxed form');
  const ok = await tryPw('opensesame', '203.0.113.2'); // another client IP (last proxy hop) is not blocked
  assert.equal(ok.status, 303);
  assert.equal(ok.headers.get('location'), '/s/alpha/');
  assert.equal((await v.fetch('/s/alpha/a.css')).status, 200);
});

test('password links: at least 8 characters; about 50 failures an hour across all IPs locks the link', async (x) => {
  const { t, admin, link } = await world(x, { trustProxy: true });
  assert.equal((await admin.post('/api/spaces/alpha/links', { password: 'short' })).status, 400);
  const l = await link('alpha', { password: 'opensesame' });
  const tryPw = (password, i) => client(t.base).fetch(path(l.url), {
    method: 'POST', body: new URLSearchParams({ password }).toString(),
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': `198.51.100.${i}` },
  });
  for (let i = 0; i < 50; i++) assert.equal((await tryPw('nope', i)).status, 401);
  assert.equal((await tryPw('opensesame', 200)).status, 429, 'a fresh IP is refused once the link is locked');
});

test('team members load team-only subresources; link spaces still admit members', async (x) => {
  const { t, admin, link } = await world(x);
  const d = await admin.fetch('/s/beta/', { headers: DOC });
  assert.equal(d.status, 200);
  assert.match(d.headers.get('set-cookie'), /SameSite=None/);
  // Sandboxed subresource requests are cross-site: the Strict session cookie would not go, the viewer cookie does.
  const viewer = [...admin.jar].find(([k]) => k.startsWith('fsv_'));
  const r = await fetch(`${t.base}/s/beta/a.css`, { headers: { cookie: `${viewer[0]}=${viewer[1]}`, 'sec-fetch-site': 'cross-site' } });
  assert.equal(r.status, 200);
  await link('alpha');
  assert.equal((await admin.fetch('/s/alpha/a.css')).status, 200);
});

test('leaving link mode disables links; coming back restores them', async (x) => {
  const { t, admin, link } = await world(x);
  const l = await link('alpha');
  const v = client(t.base);
  await v.fetch(path(l.url));
  await v.fetch('/s/alpha/', { headers: DOC });
  assert.equal((await admin.post('/api/spaces/alpha', { privacy: 'team' }, 'PATCH')).status, 200);
  assert.equal((await v.fetch('/s/alpha/a.css')).status, 401);
  assert.ok(t.db.prepare('SELECT disabled_at FROM grants WHERE id = ?').get(l.id).disabled_at);
  assert.equal((await admin.post('/api/spaces/alpha', { privacy: 'link' }, 'PATCH')).status, 200);
  assert.equal((await v.fetch('/s/alpha/a.css')).status, 200);
  const [row] = (await (await admin.fetch('/api/spaces/alpha/links')).json()).links;
  assert.equal(row.view_count, 1, 'view counts survive');
  assert.equal(row.disabled_at, null);
});

test('branding shows on the password, 404 and expired pages; bad values are refused', async (x) => {
  const { t, admin, link } = await world(x);
  assert.equal((await admin.post('/api/admin/branding', { name: 'Acme', logo: 'javascript:alert(1)' })).status, 400);
  assert.equal((await admin.post('/api/admin/branding', { name: 'Acme', accent: 'red;}' })).status, 400);
  assert.equal((await admin.post('/api/admin/branding', { name: 'Acme <Studio>', logo: 'https://acme.example/logo.png', accent: '#ff0066' })).status, 200);
  const l = await link('alpha', { password: 'long enough' });
  const pages = [await client(t.base).fetch(path(l.url)), await client(t.base).fetch('/s/nope/'), await client(t.base).fetch('/s/alpha/?key=sfl_x')];
  assert.deepEqual(pages.map((p) => p.status), [200, 404, 410]);
  assert.match(await (await admin.fetch('/instance')).text(), /value="Acme &lt;Studio&gt;"/);
  const sp = await (await admin.fetch('/spaces/alpha')).text();
  assert.match(sp, /id="sharing"/);
  assert.doesNotMatch(sp, /sfl_/, 'the URL is shown only when the link is created');
  assert.match(sp, /<option value="link" selected>/);
  for (const p of pages) {
    const h = await p.text();
    assert.match(h, /Acme &lt;Studio&gt;/);
    assert.match(h, /src="https:\/\/acme\.example\/logo\.png"/);
    assert.match(h, /#ff0066/);
  }
});

test('share keys are stored as sha256; the URL is shown once, and the dashboard form shows it once too', async (x) => {
  const { t, admin, link } = await world(x);
  const l = await link('alpha');
  const key = new URL(l.url).searchParams.get('key');
  const row = t.db.prepare('SELECT raw_token, token_hash, token_hint FROM grants WHERE id = ?').get(l.id);
  assert.deepEqual({ ...row }, { raw_token: null, token_hash: sha256hex(key), token_hint: key.slice(-4) });
  const [listed] = (await (await admin.fetch('/api/spaces/alpha/links')).json()).links;
  assert.equal(listed.url, null);
  assert.equal(listed.hint, key.slice(-4));
  const form = await admin.fetch('/api/spaces/alpha/links', { method: 'POST', body: new URLSearchParams({ _csrf: admin.csrf, label: 'Form' }).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal(form.status, 201);
  assert.match(await form.text(), /shown once.*value="https?:\/\/[^"]+\/s\/alpha\/\?key=sfl_/s);
});

test('migration 4 hashes keys stored in plaintext by migration 3', () => {
  const dir = fs.mkdtempSync(nodePath.join(os.tmpdir(), 'freespace-mig-'));
  const file = nodePath.join(dir, 'db.sqlite');
  try {
    const old = new DatabaseSync(file);
    for (const m of MIGRATIONS.slice(0, 3)) old.exec(m);
    old.exec("PRAGMA user_version = 3; INSERT INTO spaces (id,slug,name,owner_id,created_at,updated_at) VALUES ('spc_1','a','A','u','t','t');"
      + "INSERT INTO grants (id,space_id,kind,name,raw_token,created_at) VALUES ('grt_1','spc_1','share_link','L','sfl_old','t');");
    old.close();
    const db = openDb(file);
    assert.deepEqual({ ...db.prepare('SELECT raw_token, token_hash FROM grants').get() }, { raw_token: null, token_hash: sha256hex('sfl_old') });
    db.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

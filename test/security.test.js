import test from 'node:test';
import assert from 'node:assert/strict';
import { boot, client, setupAdmin } from './helpers.js';
import { SPACE_CSP, rewriteSetCookie, signViewer, verifyViewer, signDocToken, verifyDocToken, injectDocToken } from '../src/security.js';
import { PREVIEW_SANDBOX } from '../src/dashboard.js';

const files = (o) => Object.entries(o).map(([path, content]) => ({ path, content }));

async function withSpace(t, privacy = 'team', fileMap = { 'index.html': '<h1>hi</h1>', 'a.css': 'x{}' }, slug = 'demo') {
  const admin = await setupAdmin(t);
  await admin.post('/api/spaces', { name: 'Demo', slug });
  const r = await admin.post(`/api/spaces/${slug}/versions`, { files: files(fileMap) });
  assert.equal(r.status, 201, await r.clone().text());
  if (privacy !== 'team') assert.equal((await admin.post(`/api/spaces/${slug}`, { privacy }, 'PATCH')).status, 200);
  return admin;
}

test('rule 1: sandbox CSP on every status and content type', async (x) => {
  const t = await boot(); x.after(t.close);
  await withSpace(t, 'public', { 'index.html': 'hi', 'a.css': 'x{}', 'b.png': 'png', '404.html': 'nope', 'm.pdf': 'pdf' });
  const c = client(t.base);
  for (const [p, status] of [['/s/demo/', 200], ['/s/demo/a.css', 200], ['/s/demo/b.png', 200], ['/s/demo/m.pdf', 200], ['/s/demo/missing', 404], ['/s/nope/', 404], ['/s/demo', 308]]) {
    const r = await c.fetch(p);
    assert.equal(r.status, status, p);
    assert.equal(r.headers.get('content-security-policy'), SPACE_CSP, p);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  }
  const post = await c.fetch('/s/demo/', { method: 'POST' });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get('content-security-policy'), SPACE_CSP);
  assert.doesNotMatch(SPACE_CSP, /allow-same-origin|popups-to-escape|top-navigation/);
});

test('rule 2: _headers cannot set reserved headers; dropped with a warning', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await withSpace(t, 'public', {
    'index.html': 'hi',
    '_headers': '/*\n  Content-Security-Policy: default-src *\n  Set-Cookie: a=b\n  Access-Control-Allow-Origin: *\n  Cross-Origin-Opener-Policy: unsafe-none\n  Service-Worker-Allowed: /\n  X-Custom: ok\n',
  });
  const r = await client(t.base).fetch('/s/demo/');
  assert.equal(r.headers.get('content-security-policy'), SPACE_CSP);
  assert.equal(r.headers.get('set-cookie'), null);
  assert.equal(r.headers.get('access-control-allow-origin'), null);
  assert.equal(r.headers.get('cross-origin-opener-policy'), null);
  assert.equal(r.headers.get('service-worker-allowed'), null);
  assert.equal(r.headers.get('x-custom'), 'ok');
  const v = await (await admin.fetch('/api/spaces/demo/versions')).json();
  assert.ok(v.versions.length);
  const warns = JSON.parse(t.db.prepare('SELECT warnings_json FROM versions ORDER BY created_at DESC').get().warnings_json);
  assert.ok(warns.some((w) => /content-security-policy/i.test(w)), JSON.stringify(warns));
});

test('rule 3: dashboard session cookie attributes', async (x) => {
  const t = await boot(); x.after(t.close);
  const r = await client(t.base).json('/api/setup', { name: 'A', email: 'a@example.com', password: 'longenoughpass' });
  const sc = r.headers.getSetCookie()[0];
  assert.match(sc, /^__Host-fs_session=/);
  for (const a of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/']) assert.ok(sc.includes(a), a);
  assert.ok(!/Domain=/i.test(sc));
});

test('rule 4: writes need CSRF + same-origin; Origin null refused; bearer exempt', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await setupAdmin(t);
  const ok = await admin.post('/api/spaces', { name: 'One' });
  assert.equal(ok.status, 201);
  const noCsrf = await admin.json('/api/spaces', { name: 'Two' });
  assert.equal(noCsrf.status, 403);
  const badCsrf = await admin.json('/api/spaces', { name: 'Two' }, 'POST', { 'x-csrf-token': 'nope' });
  assert.equal(badCsrf.status, 403);
  const cross = await admin.json('/api/spaces', { name: 'Two' }, 'POST', { 'x-csrf-token': admin.csrf, 'sec-fetch-site': 'cross-site' });
  assert.equal(cross.status, 403);
  const none = await admin.json('/api/spaces', { name: 'Two' }, 'POST', { 'x-csrf-token': admin.csrf, 'sec-fetch-site': 'none' });
  assert.equal(none.status, 403);
  const nullOrigin = await admin.json('/api/spaces', { name: 'Two' }, 'POST', { 'x-csrf-token': admin.csrf, origin: 'null' });
  assert.equal(nullOrigin.status, 403);
  // bearer requests skip the cookie checks (they get a 401 here only because the token is unknown)
  const bearer = await client(t.base).json('/api/spaces', { name: 'x' }, 'POST', { authorization: 'Bearer fsa_unknowntokenvalue', 'sec-fetch-site': 'cross-site' });
  assert.equal(bearer.status, 401);
});

test('rule 5: plugin Set-Cookie is rewritten and reserved names dropped', () => {
  const space = { id: 'spc_abcdefghijklmnop', slug: 'demo' };
  const out = rewriteSetCookie(['sid=1; Path=/; Domain=evil.com; HttpOnly; SameSite=Lax', '__Host-fs_session=x', 'fsv_abc=y', 'fs_x=1'], space);
  assert.equal(out.length, 1);
  assert.match(out[0], /^fsp_abcdefgh_sid=1; Path=\/s\/demo\/; Secure; SameSite=None; HttpOnly$/);
  assert.ok(!/Domain/i.test(out[0]));
});

test('rule 6: viewer cookies are bound to their space', () => {
  const A = { id: 'spc_aaaaaaaaaaaaaaaa', slug: 'a' }, B = { id: 'spc_bbbbbbbbbbbbbbbb', slug: 'b' };
  const s = signViewer('secret', A, 'usr_1', 60000);
  assert.deepEqual(verifyViewer('secret', A, s.value), { kind: 'team', subject: 'usr_1' });
  assert.equal(verifyViewer('secret', B, s.value), null);
  assert.equal(verifyViewer('other', A, s.value), null);
  assert.equal(verifyViewer('secret', A, s.value + 'x'), null);
  assert.equal(verifyViewer('secret', A, signViewer('secret', A, 'u', -1).value), null);
});

test('team-only space: login mints a space-bound HttpOnly viewer cookie; removed member loses access', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await withSpace(t);
  const anon = client(t.base);
  assert.equal((await anon.fetch('/s/demo/', { headers: { accept: 'text/html', 'sec-fetch-dest': 'document' } })).status, 302);
  assert.equal((await anon.fetch('/s/demo/a.css')).status, 401);
  const r = await admin.fetch('/s/demo/', { headers: { 'sec-fetch-dest': 'document' } });
  assert.equal(r.status, 200);
  const vc = r.headers.getSetCookie().find((c) => c.startsWith('fsv_'));
  assert.ok(vc.includes('HttpOnly') && vc.includes('Secure') && vc.includes('SameSite=None') && vc.includes('Path=/s/demo/'));
  // the viewer cookie alone (no dashboard session) now opens assets
  const viewer = client(t.base);
  const [k, v] = vc.split(';')[0].split('=');
  viewer.jar.set(k, v.slice(0));
  assert.equal((await viewer.fetch('/s/demo/a.css')).status, 200);
  t.db.prepare('UPDATE users SET disabled_at = ?').run('2020-01-01T00:00:00Z');
  assert.equal((await viewer.fetch('/s/demo/a.css')).status, 401);
});

test('rule 7: doc token is space-bound and injected into documents only', () => {
  const A = { id: 'spc_aaaaaaaaaaaaaaaa' }, B = { id: 'spc_bbbbbbbbbbbbbbbb' };
  const tok = signDocToken('s', A);
  assert.ok(verifyDocToken('s', A, tok));
  assert.ok(!verifyDocToken('s', B, tok));
  assert.ok(!verifyDocToken('s', A, signDocToken('s', A, undefined, -1)));
  assert.deepEqual(verifyDocToken('s', A, signDocToken('s', A, { kind: 'link', subject: 'grt_x' })), { kind: 'link', subject: 'grt_x' });
  assert.match(injectDocToken('<html><head><title>x</title></head>', tok), /<head><meta name="freespace-doc-token" content="/);
});

test('rule 8: preview iframe is sandboxed without allow-same-origin', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await withSpace(t);
  const page = await (await admin.fetch('/spaces/demo')).text();
  const m = /<iframe[^>]*sandbox="([^"]*)"/.exec(page);
  assert.ok(m, 'iframe has sandbox attr');
  assert.equal(m[1], PREVIEW_SANDBOX);
  assert.doesNotMatch(m[1], /allow-same-origin/);
});

test('rule 1: CSP on 304, 416, 400, team 302/401, HEAD and 500', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await withSpace(t, 'team', { 'index.html': 'hi', 'a.css': 'x{}' });
  const anon = client(t.base);
  const etag = (await admin.fetch('/s/demo/a.css')).headers.get('etag');
  const cases = [
    [admin, '/s/demo/a.css', 304, { headers: { 'if-none-match': etag } }],
    [admin, '/s/demo/a.css', 416, { headers: { range: 'bytes=99-' } }],
    [admin, '/s/demo/%E0%A4%A', 400],
    [anon, '/s/demo/', 302, { headers: { 'sec-fetch-dest': 'document' } }],
    [anon, '/s/demo/a.css', 401],
    [admin, '/s/demo/a.css', 200, { method: 'HEAD' }],
  ];
  for (const [c, p, status, init] of cases) {
    const r = await c.fetch(p, init);
    assert.equal(r.status, status, p);
    assert.equal(r.headers.get('content-security-policy'), SPACE_CSP, `${status} ${p}`);
  }
  t.db.prepare("UPDATE versions SET routing_json = '{'").run(); // force an internal error
  const r = await admin.fetch('/s/demo/a.css');
  assert.equal(r.status, 500);
  assert.equal(r.headers.get('content-security-policy'), SPACE_CSP);
});

test('rule 2: host-scoped headers from _headers never reach a response', async (x) => {
  const t = await boot(); x.after(t.close);
  await withSpace(t, 'public', { 'index.html': 'hi', '_headers': '/*\n  Strict-Transport-Security: max-age=0\n  Clear-Site-Data: "*"\n  Set-Login: logged-out\n  Permissions-Policy: camera=*\n' });
  const r = await client(t.base).fetch('/s/demo/');
  for (const h of ['strict-transport-security', 'clear-site-data', 'set-login', 'permissions-policy']) assert.equal(r.headers.get(h), null, h);
});

test('rule 4: unauthenticated writes are refused; logout is not a GET', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await withSpace(t);
  const anon = client(t.base);
  assert.equal((await anon.json('/api/spaces', { name: 'x' })).status, 401);
  assert.equal((await anon.fetch('/api/spaces/demo/versions', { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })).status, 401);
  assert.equal((await anon.fetch('/api/spaces/demo/upload', { method: 'POST', body: 'x', headers: { 'content-type': 'application/zip' } })).status, 401);
  assert.notEqual((await admin.fetch('/api/logout')).status, 200);
  assert.equal((await admin.fetch('/api/me')).status, 200); // GET left the session alive
});

test('rule 6: a viewer cookie for space A is rejected on space B over HTTP', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await withSpace(t, 'team', { 'index.html': 'a' }, 'a');
  await admin.post('/api/spaces', { name: 'B', slug: 'b' });
  await admin.post('/api/spaces/b/versions', { files: files({ 'index.html': 'b' }) });
  const vc = (await admin.fetch('/s/a/', { headers: { 'sec-fetch-dest': 'document' } })).headers.getSetCookie().find((c) => c.startsWith('fsv_'));
  const value = vc.split(';')[0].split('=')[1];
  const bId = t.db.prepare("SELECT id FROM spaces WHERE slug = 'b'").get().id;
  const thief = client(t.base);
  thief.jar.set(`fsv_${bId.slice(4, 12)}`, value);
  assert.equal((await thief.fetch('/s/b/')).status, 401);
});

test('rule 7: the doc token goes only to documents (Sec-Fetch-Dest), never to other requests', async (x) => {
  const t = await boot(); x.after(t.close);
  await withSpace(t, 'public', { 'index.html': '<head></head>hi', 'a.css': 'x{}' });
  t.plugins.setInstanceEnabled('sqlite', true);
  t.db.prepare(`UPDATE spaces SET plugins_json = '["sqlite"]'`).run();
  const c = client(t.base);
  const body = async (p, dest) => (await c.fetch(p, { headers: dest ? { 'sec-fetch-dest': dest } : {} })).text();
  assert.match(await body('/s/demo/', 'document'), /freespace-doc-token/);
  for (const [p, dest] of [['/s/demo/', 'empty'], ['/s/demo/', 'script'], ['/s/demo/', undefined], ['/s/demo/a.css', 'document']]) {
    assert.doesNotMatch(await body(p, dest), /freespace-doc-token/, `${p} ${dest}`);
  }
});

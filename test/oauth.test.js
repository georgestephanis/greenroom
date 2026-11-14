// M2: OAuth 2.1 + MCP. One test per security property in issue #214 section 6.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { boot, client, setupAdmin } from './helpers.js';
import { parseScopeString } from '../src/auth.js';
import { isPrivateIp, fetchJson } from '../src/ssrf.js';

const CLIENT = 'https://claude.example/oauth/client.json';
const REDIRECT = 'https://claude.example/callback';
const DOCS = {
  [CLIENT]: { client_id: CLIENT, client_name: 'Claude', redirect_uris: [REDIRECT] },
  'https://evil.example/c.json': { client_id: 'https://claude.example/oauth/client.json', client_name: 'Claude', redirect_uris: ['https://evil.example/cb'] },
};
const fetchClientMetadata = async (url) => { if (!DOCS[url]) throw new Error('HTTP 404'); return DOCS[url]; };

async function world() {
  const t = await boot({ fetchClientMetadata });
  const ada = await setupAdmin(t);
  for (const name of ['alpha', 'beta']) assert.equal((await ada.post('/api/spaces', { name })).status, 201);
  return { t, ada };
}
const form = (c, p, pairs, headers = {}) =>
  c.fetch(p, { method: 'POST', body: new URLSearchParams(pairs).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers } });
const pkce = () => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
};
const authzQuery = (o) => '/oauth/authorize?' + new URLSearchParams({ response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, state: 'st', code_challenge_method: 'S256', ...o });

/** Full browser + client dance: consent as `person`, exchange the code. Returns the token response. */
async function connect(t, person, { spaces = ['alpha'], perms = ['read'], create = false, scope = 'read' } = {}) {
  const { verifier, challenge } = pkce();
  const q = { code_challenge: challenge, scope };
  assert.equal((await person.fetch(authzQuery(q))).status, 200);
  const pairs = [['_csrf', person.csrf], ...Object.entries({ response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, state: 'st', code_challenge_method: 'S256', ...q }),
    ...spaces.map((s) => ['spaces', s]), ...perms.map((p) => ['perms', p]), ...(create ? [['create', '1']] : []), ['decision', 'approve']];
  const r = await form(person, '/oauth/authorize', pairs);
  assert.equal(r.status, 303, await r.text());
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, REDIRECT);
  assert.equal(loc.searchParams.get('state'), 'st');
  const code = loc.searchParams.get('code');
  const tok = await form(client(t.base), '/oauth/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: verifier }, { 'sec-fetch-site': 'cross-site' });
  assert.equal(tok.status, 200);
  return { ...(await tok.json()), code, verifier };
}
async function mcp(t, token, method, params = {}) {
  const r = await fetch(t.base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', ...(token && { authorization: `Bearer ${token}` }) }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  return { status: r.status, www: r.headers.get('www-authenticate'), body: r.status === 202 ? null : await r.json() };
}
const call = (t, token, name, args = {}) => mcp(t, token, 'tools/call', { name, arguments: args });
const refresh = (t, rt) => form(client(t.base), '/oauth/token', { grant_type: 'refresh_token', refresh_token: rt, client_id: CLIENT });

test('discovery: /mcp 401 points at RFC 9728 metadata, which points at RFC 8414 metadata', async () => {
  const { t } = await world();
  try {
    const r = await mcp(t, null, 'initialize');
    assert.equal(r.status, 401);
    const prm = /resource_metadata="([^"]+)"/.exec(r.www)[1];
    const pr = await (await fetch(t.base + new URL(prm).pathname)).json();
    assert.match(pr.resource, /\/mcp$/);
    const iss = pr.authorization_servers[0];
    const as = await (await fetch(t.base + '/.well-known/oauth-authorization-server')).json();
    assert.equal(as.issuer, iss);
    assert.deepEqual(as.code_challenge_methods_supported, ['S256']);
    assert.equal(as.client_id_metadata_document_supported, true);
    assert.equal(as.registration_endpoint, undefined, 'DCR is off by default');
    // A dashboard session cookie never authenticates MCP.
    const ada = client(t.base);
    assert.equal((await ada.fetch('/mcp', { method: 'POST' })).status, 401);
  } finally { t.close(); }
});

test('DCR is off by default; only an admin session can turn it on', async () => {
  const { t, ada } = await world();
  try {
    const reg = (uri = 'https://x.example/cb') => fetch(t.base + '/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'X', redirect_uris: [uri] }) });
    assert.equal((await reg()).status, 403);
    const { access_token } = await connect(t, ada, { perms: ['read', 'publish'] });
    assert.equal((await fetch(t.base + '/api/admin/dcr', { method: 'POST', headers: { authorization: `Bearer ${access_token}`, 'content-type': 'application/json' }, body: '{"enabled":true}' })).status, 403);
    assert.equal((await ada.post('/api/admin/dcr', { enabled: true })).status, 200);
    assert.equal((await reg()).status, 201);
    // https, or http on loopback only.
    for (const u of ['http://127.0.0.1:3000/cb', 'http://localhost/cb', 'http://[::1]:9/cb']) assert.equal((await reg(u)).status, 201, u);
    for (const u of ['http://x.example/cb', 'myapp://cb', 'javascript:alert(1)']) assert.equal((await (await reg(u)).json()).error, 'invalid_redirect_uri', u);
  } finally { t.close(); }
});

test('CIMD: client_id must be https, match its document, and list the redirect_uri; SSRF guard blocks private hosts', async () => {
  const { t, ada } = await world();
  try {
    const { challenge } = pkce();
    for (const q of [
      { client_id: 'http://claude.example/oauth/client.json' },
      { client_id: 'https://evil.example/c.json', redirect_uri: 'https://evil.example/cb' }, // document claims another client_id
      { redirect_uri: 'https://attacker.example/cb' }, // not registered: shown, never redirected
      { client_id: 'https://missing.example/c.json' },
    ]) {
      const r = await ada.fetch(authzQuery({ code_challenge: challenge, scope: 'read', ...q }));
      assert.equal(r.status, 400, JSON.stringify(q));
      assert.equal(r.headers.get('location'), null);
    }
    for (const ip of ['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.0.1', '::1', 'fd00::1', '::ffff:127.0.0.1']) assert.ok(isPrivateIp(ip), ip);
    assert.ok(!isPrivateIp('93.184.216.34'));
    await assert.rejects(fetchJson('https://127.0.0.1/c.json'), /Blocked private address/);
    await assert.rejects(fetchJson('https://[::1]/c.json'), /Blocked private address/);
    await assert.rejects(fetchJson('https://localhost/c.json'), /public https/);
  } finally { t.close(); }
});

test('PKCE is required and verified; codes are single-use and a replay revokes the grant', async () => {
  const { t, ada } = await world();
  try {
    const noPkce = () => ada.fetch(authzQuery({ scope: 'read' }).replace('&code_challenge_method=S256', ''));
    const shown = await noPkce();
    assert.equal(shown.status, 400, 'errors for a client never approved are shown, not redirected (open redirect)');
    assert.equal(shown.headers.get('location'), null);
    assert.match(await shown.text(), /invalid_request/);
    await connect(t, ada);
    const back = await noPkce(); // an approved client gets the RFC 6749 error redirect
    assert.equal(back.status, 302);
    assert.equal(new URL(back.headers.get('location')).searchParams.get('error'), 'invalid_request');

    const { verifier, challenge } = pkce();
    const pairs = [['_csrf', ada.csrf], ['response_type', 'code'], ['client_id', CLIENT], ['redirect_uri', REDIRECT], ['code_challenge', challenge], ['code_challenge_method', 'S256'], ['spaces', 'alpha'], ['perms', 'read'], ['decision', 'approve']];
    const code = new URL((await form(ada, '/oauth/authorize', pairs)).headers.get('location')).searchParams.get('code');
    const bad = await form(client(t.base), '/oauth/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: pkce().verifier });
    assert.equal((await bad.json()).error, 'invalid_grant');
    // Wrong client_id or redirect_uri fail too, and none of these burn the code for the real client.
    for (const p of [{ client_id: 'https://other.example/c.json' }, { redirect_uri: 'https://claude.example/other' }]) {
      const r = await form(client(t.base), '/oauth/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: verifier, ...p });
      assert.equal((await r.json()).error, 'invalid_grant', JSON.stringify(p));
    }
    const real = await form(client(t.base), '/oauth/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: verifier });
    assert.equal(real.status, 200);

    // An expired code is refused.
    const { verifier: v2, challenge: c2 } = pkce();
    const code2 = new URL((await form(ada, '/oauth/authorize', pairs.map(([k, v]) => [k, k === 'code_challenge' ? c2 : v]))).headers.get('location')).searchParams.get('code');
    t.db.prepare("UPDATE oauth_codes SET expires_at = '2000-01-01T00:00:00.000Z' WHERE used_at IS NULL").run();
    const expired = await form(client(t.base), '/oauth/token', { grant_type: 'authorization_code', code: code2, redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: v2 });
    assert.match((await expired.json()).error_description, /expired/);

    const ok = await connect(t, ada);
    assert.equal((await mcp(t, ok.access_token, 'ping')).status, 200);
    const replay = await form(client(t.base), '/oauth/token', { grant_type: 'authorization_code', code: ok.code, redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: ok.verifier });
    assert.equal((await replay.json()).error, 'invalid_grant');
    assert.equal((await mcp(t, ok.access_token, 'ping')).status, 401, 'replayed code revokes what it issued');
  } finally { t.close(); }
});

test('unknown scope strings fail closed everywhere', async () => {
  const { t, ada } = await world();
  try {
    assert.throws(() => parseScopeString('read admin'), /Unknown scope: admin/);
    assert.throws(() => parseScopeString('space:*'), /Unknown scope/);
    assert.deepEqual(parseScopeString('space:alpha spaces:create publish'), { spaces: ['alpha'], create: true, perms: ['publish'], readOnly: false });
    const { refresh_token } = await connect(t, ada);
    const r = await ada.fetch(authzQuery({ code_challenge: pkce().challenge, scope: 'read superuser' }));
    assert.equal(new URL(r.headers.get('location')).searchParams.get('error'), 'invalid_scope');
    const rr = await form(client(t.base), '/oauth/token', { grant_type: 'refresh_token', refresh_token, client_id: CLIENT, scope: 'read sudo' });
    assert.equal((await rr.json()).error, 'invalid_scope');
    // Consent form with a forged permission: no code is issued.
    const pairs = [['_csrf', ada.csrf], ['response_type', 'code'], ['client_id', CLIENT], ['redirect_uri', REDIRECT], ['code_challenge', pkce().challenge], ['code_challenge_method', 'S256'], ['perms', 'admin'], ['decision', 'approve']];
    assert.equal(new URL((await form(ada, '/oauth/authorize', pairs)).headers.get('location')).searchParams.get('error'), 'invalid_scope');
    assert.equal((await form(ada, '/api/tokens', [['_csrf', ada.csrf], ['name', 'x'], ['perms', 'root']])).status, 400);
    assert.equal(t.db.prepare("SELECT COUNT(*) c FROM api_keys WHERE kind = 'agent_token'").get().c, 0);
  } finally { t.close(); }
});

test('revoking a grant kills both its access and refresh tokens', async () => {
  const { t, ada } = await world();
  try {
    const a = await connect(t, ada);
    const grant = t.db.prepare("SELECT id FROM api_keys WHERE kind = 'oauth'").get().id;
    assert.equal((await ada.post(`/api/tokens/${grant}/revoke`, {})).status, 200);
    assert.equal((await mcp(t, a.access_token, 'ping')).status, 401);
    assert.equal((await (await refresh(t, a.refresh_token)).json()).error, 'invalid_grant');
    assert.equal(t.db.prepare('SELECT COUNT(*) c FROM oauth_tokens WHERE grant_id = ?').get(grant).c, 0);

    // RFC 7009 revocation with the refresh token does the same.
    const b = await connect(t, ada);
    assert.equal((await form(client(t.base), '/oauth/revoke', { token: b.refresh_token })).status, 200);
    assert.equal((await mcp(t, b.access_token, 'ping')).status, 401);
  } finally { t.close(); }
});

test('refresh tokens rotate; reusing a spent one revokes the grant', async () => {
  const { t, ada } = await world();
  try {
    const a = await connect(t, ada);
    const b = await (await refresh(t, a.refresh_token)).json();
    assert.ok(b.access_token && b.refresh_token && b.refresh_token !== a.refresh_token);
    assert.equal((await mcp(t, a.access_token, 'ping')).status, 401, 'old access token retired on refresh');
    assert.equal((await mcp(t, b.access_token, 'ping')).status, 200);
    assert.equal((await (await refresh(t, a.refresh_token)).json()).error, 'invalid_grant');
    assert.equal((await mcp(t, b.access_token, 'ping')).status, 401, 'reuse detection revoked the whole grant');
    assert.equal((await (await refresh(t, b.refresh_token)).json()).error, 'invalid_grant');
  } finally { t.close(); }
});

test('the granter is a live constraint: disabling them kills their grants and tokens', async () => {
  const { t, ada } = await world();
  try {
    const inv = (await (await ada.post('/api/invites', {})).json()).invite;
    const bob = client(t.base);
    assert.equal((await bob.json('/api/invites/accept', { token: inv.split('/').pop(), name: 'Bob', email: 'bob@example.com', password: 'correct horse battery' })).status, 201);
    bob.csrf = t.db.prepare('SELECT s.csrf_token FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = ?').get('bob@example.com').csrf_token;
    const a = await connect(t, bob);
    assert.equal((await mcp(t, a.access_token, 'ping')).status, 200);
    const bobId = t.db.prepare("SELECT id FROM users WHERE username = 'bob@example.com'").get().id;
    assert.equal((await ada.post(`/api/users/${bobId}/deactivate`, {})).status, 200);
    assert.equal((await mcp(t, a.access_token, 'ping')).status, 401);
    assert.equal((await (await refresh(t, a.refresh_token)).json()).error, 'invalid_grant');
  } finally { t.close(); }
});

test('escalation is closed: OAuth and pasted tokens cannot make a space public, mint tokens, invite, or approve grants', async () => {
  const { t, ada } = await world();
  try {
    const { access_token } = await connect(t, ada, { spaces: ['alpha'], perms: ['read', 'publish', 'share', 'db', 'export'], create: true });
    const minted = await form(ada, '/api/tokens', [['_csrf', ada.csrf], ['name', 'Deploy bot'], ['spaces', 'alpha'], ['perms', 'publish'], ['perms', 'read']]);
    const fsa = /value="(gra_[^"]+)"/.exec(await minted.text())[1];
    for (const token of [access_token, fsa]) {
      const h = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
      const req = (p, body, method = 'POST') => fetch(t.base + p, { method, headers: h, body: JSON.stringify(body) });
      assert.equal((await req('/api/spaces/alpha', { privacy: 'public' }, 'PATCH')).status, 403);
      assert.equal((await req('/api/tokens', { name: 'x', perms: ['read'] })).status, 403);
      assert.equal((await req('/api/invites', {})).status, 403);
      assert.equal((await req('/api/spaces/alpha', {}, 'DELETE')).status, 403);
      const approve = await fetch(t.base + '/oauth/authorize', { method: 'POST', headers: { ...h, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: CLIENT, redirect_uri: REDIRECT, response_type: 'code', code_challenge: pkce().challenge, code_challenge_method: 'S256', perms: 'read', decision: 'approve' }) });
      assert.equal(approve.status, 403);
      const tools = (await mcp(t, token, 'tools/list')).body.result.tools.map((x) => x.name);
      assert.ok(!tools.some((n) => /privacy|public|token|user|invite/.test(n)), tools.join());
    }
    assert.equal(t.store.space('alpha').privacy, 'team');
    const page = await (await ada.fetch('/access')).text();
    assert.match(page, /Claude — https:\/\/claude\.example/);
    assert.match(page, /Deploy bot/);
  } finally { t.close(); }
});

test('insufficient_scope names what to ask for, and step-up widens the same grant', async () => {
  const { t, ada } = await world();
  try {
    const a = await connect(t, ada, { spaces: ['alpha'], perms: ['read'] });
    const pub = await call(t, a.access_token, 'publish', { slug: 'alpha', files: [{ path: 'index.html', content: 'hi' }] });
    assert.equal(pub.status, 403);
    assert.match(pub.www, /error="insufficient_scope", scope="space:alpha read publish"/);
    const other = await call(t, a.access_token, 'get_space', { slug: 'beta' });
    assert.match(other.www, /scope="space:alpha read space:beta"/);
    // A missing space looks exactly like one outside the grant.
    const nope = await call(t, a.access_token, 'get_space', { slug: 'nope' });
    assert.equal(nope.status, other.status);
    assert.equal(nope.body.error.message.replace('nope', 'beta'), other.body.error.message);
    assert.deepEqual((await call(t, a.access_token, 'list_spaces')).body.result.structuredContent.spaces.map((s) => s.slug), ['alpha']);

    await connect(t, ada, { spaces: ['alpha', 'beta'], perms: ['read', 'publish'], scope: 'space:alpha space:beta read publish' });
    assert.equal(t.db.prepare("SELECT COUNT(*) c FROM api_keys WHERE kind = 'oauth' AND revoked_at IS NULL").get().c, 1, 'one grant per member+client');
    assert.equal((await call(t, a.access_token, 'publish', { slug: 'beta', files: [{ path: 'index.html', content: 'hi' }] })).status, 200);
  } finally { t.close(); }
});

test('MCP tools: create_space joins the grant, publish/read/diff/rollback work, history says "Claude (via Ada)"', async () => {
  const { t, ada } = await world();
  try {
    const { access_token: tok } = await connect(t, ada, { spaces: [], perms: ['read', 'publish'], create: true, scope: 'spaces:create read publish' });
    const init = (await mcp(t, tok, 'initialize', { protocolVersion: '1999-01-01' })).body.result;
    assert.equal(init.serverInfo.name, 'greenroom');
    assert.equal(init.protocolVersion, '2025-06-18', 'answers with a version it supports, not an echo');
    const made = await call(t, tok, 'create_space', { name: 'Gamma' });
    assert.equal(made.body.result.structuredContent.space.slug, 'gamma');
    const r1 = await call(t, tok, 'publish', { slug: 'gamma', files: [{ path: 'index.html', content: '<h1>one</h1>' }], message: 'first' });
    assert.ok(!r1.body.result.isError, JSON.stringify(r1.body));
    await call(t, tok, 'publish', { slug: 'gamma', files: [{ path: 'b.txt', content: 'two' }], base: 'live', message: 'second' });
    const rf = await call(t, tok, 'read_file', { slug: 'gamma', path: 'index.html' });
    const read = rf.body.result.structuredContent;
    assert.equal(read.content, '<h1>one</h1>');
    const versions = (await call(t, tok, 'list_versions', { slug: 'gamma' })).body.result.structuredContent.versions;
    assert.deepEqual(versions.map((v) => v.author), ['Claude (via Ada)', 'Claude (via Ada)']);
    assert.deepEqual((await call(t, tok, 'diff_versions', { slug: 'gamma', from: 1, to: 2 })).body.result.structuredContent.added.map((f) => f.path), ['b.txt']);
    assert.equal((await call(t, tok, 'rollback', { slug: 'gamma', version: 1 })).body.result.structuredContent.version.number, 3);
    assert.equal((await call(t, tok, 'get_space', { slug: 'alpha' })).status, 403, 'creating a space does not widen to others');
  } finally { t.close(); }
});

test('consent needs a signed-in person; login returns to the full authorize URL', async () => {
  const { t } = await world();
  try {
    const r = await client(t.base).fetch(authzQuery({ code_challenge: pkce().challenge, scope: 'read' }));
    assert.equal(r.status, 302);
    const next = new URL(r.headers.get('location'), t.base).searchParams.get('next');
    assert.match(next, /^\/oauth\/authorize\?.*code_challenge=/);
  } finally { t.close(); }
});

test('MCP resolves the grant after the body arrives; concurrent create_space calls both join it', async () => {
  const { t, ada } = await world();
  try {
    const { access_token: tok } = await connect(t, ada, { spaces: [], perms: ['read'], create: true, scope: 'spaces:create read' });
    await Promise.all(['one', 'two', 'three'].map((name) => call(t, tok, 'create_space', { name })));
    assert.deepEqual(JSON.parse(t.db.prepare("SELECT scope_json FROM api_keys WHERE kind = 'oauth'").get().scope_json).spaces.sort(), ['one', 'three', 'two']);

    // A request whose body is still arriving when the grant is revoked must not run.
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'create_space', arguments: { name: 'late' } } });
    const status = await new Promise((resolve, reject) => {
      const req = http.request(t.base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json', 'content-length': body.length } }, (res) => { res.resume(); resolve(res.statusCode); });
      req.on('error', reject);
      req.write(body.slice(0, 10));
      setTimeout(async () => {
        assert.equal((await ada.post(`/api/tokens/${t.db.prepare("SELECT id FROM api_keys WHERE kind = 'oauth'").get().id}/revoke`, {})).status, 200);
        req.end(body.slice(10));
      }, 50);
    });
    assert.equal(status, 401);
    assert.equal(t.store.space('late'), undefined);
  } finally { t.close(); }
});

test('step-up with the server hint keeps what the grant had; consent pre-ticks the existing grant', async () => {
  const { t, ada } = await world();
  try {
    const a = await connect(t, ada, { spaces: ['alpha'], perms: ['read'] });
    const ticked = async (scope) => {
      const page = await (await ada.fetch(authzQuery({ code_challenge: pkce().challenge, scope }))).text();
      return [...page.matchAll(/name="(spaces|perms|create)" value="([^"]+)" checked/g)].map((m) => `${m[1]}=${m[2]}`).sort();
    };
    // A client that asks only for the missing piece still sees the existing grant ticked.
    assert.deepEqual(await ticked('publish'), ['perms=publish', 'perms=read', 'spaces=alpha']);

    const hint = /scope="([^"]+)"/.exec((await call(t, a.access_token, 'publish', { slug: 'beta', files: [{ path: 'index.html', content: 'hi' }] })).www)[1];
    const boxes = await ticked(hint);
    const pick = (k) => boxes.filter((b) => b.startsWith(k + '=')).map((b) => b.split('=')[1]);
    await connect(t, ada, { spaces: pick('spaces'), perms: pick('perms'), scope: hint });
    assert.equal((await call(t, a.access_token, 'publish', { slug: 'beta', files: [{ path: 'index.html', content: 'hi' }] })).status, 200);
    assert.equal((await call(t, a.access_token, 'get_space', { slug: 'alpha' })).status, 200, 'alpha is still in scope');
  } finally { t.close(); }
});

test('consent POST needs the CSRF token and a same-origin fetch', async () => {
  const { t, ada } = await world();
  try {
    const q = { response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, state: 'st', code_challenge_method: 'S256', code_challenge: pkce().challenge, scope: 'read' };
    const pairs = [...Object.entries(q), ['spaces', 'alpha'], ['perms', 'read'], ['decision', 'approve']];
    assert.equal((await form(ada, '/oauth/authorize', pairs)).status, 403, 'no _csrf');
    assert.equal((await form(ada, '/oauth/authorize', [['_csrf', ada.csrf], ...pairs], { 'sec-fetch-site': 'cross-site' })).status, 403, 'cross-site');
    assert.equal(t.db.prepare('SELECT COUNT(*) c FROM oauth_codes').get().c, 0);
  } finally { t.close(); }
});

test('a refresh token presented by another client_id fails without spending it', async () => {
  const { t, ada } = await world();
  try {
    const a = await connect(t, ada);
    const other = await form(client(t.base), '/oauth/token', { grant_type: 'refresh_token', refresh_token: a.refresh_token, client_id: 'https://other.example/c.json' });
    assert.equal((await other.json()).error, 'invalid_grant');
    assert.equal((await refresh(t, a.refresh_token)).status, 200);
  } finally { t.close(); }
});

test('gra_ tokens: the owner can revoke one; another non-admin member cannot', async () => {
  const { t, ada } = await world();
  try {
    const mint = async () => {
      const r = await form(ada, '/api/tokens', [['_csrf', ada.csrf], ['name', 'bot'], ['spaces', 'alpha'], ['perms', 'read']]);
      const fsa = /value="(gra_[^"]+)"/.exec(await r.text())[1];
      return { fsa, id: t.db.prepare("SELECT id FROM api_keys WHERE kind != 'oauth' ORDER BY rowid DESC").get().id };
    };
    const inv = (await (await ada.post('/api/invites', {})).json()).invite;
    const bob = client(t.base);
    assert.equal((await bob.json('/api/invites/accept', { token: inv.split('/').pop(), name: 'Bob', email: 'bob@example.com', password: 'correct horse battery' })).status, 201);
    const bobCsrf = t.db.prepare('SELECT s.csrf_token FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = ?').get('bob@example.com').csrf_token;

    const one = await mint();
    assert.equal((await mcp(t, one.fsa, 'ping')).status, 200);
    assert.equal((await bob.json(`/api/tokens/${one.id}/revoke`, {}, 'POST', { 'x-csrf-token': bobCsrf })).status, 404);
    assert.equal((await mcp(t, one.fsa, 'ping')).status, 200, "Bob's attempt changed nothing");
    assert.equal((await ada.post(`/api/tokens/${one.id}/revoke`, {})).status, 200);
    assert.equal((await mcp(t, one.fsa, 'ping')).status, 401);
  } finally { t.close(); }
});

test('read_file: binary comes back as base64; files over 5 MB are refused', async () => {
  const { t, ada } = await world();
  try {
    const { access_token: tok } = await connect(t, ada, { perms: ['read', 'publish'], scope: 'space:alpha read publish' });
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1, 2, 255]);
    const big = await t.store.cas.storeBuffer(Buffer.alloc(6 * 1024 * 1024, 'a'));
    const pub = await call(t, tok, 'publish', { slug: 'alpha', files: [{ path: 'a.png', base64: png.toString('base64') }, { path: 'big.txt', sha256: big.sha256 }] });
    assert.ok(!pub.body.result.isError, JSON.stringify(pub.body));
    const img = (await call(t, tok, 'read_file', { slug: 'alpha', path: 'a.png' })).body.result.structuredContent;
    assert.equal(img.base64, png.toString('base64'));
    assert.equal(img.content, undefined);
    const huge = (await call(t, tok, 'read_file', { slug: 'alpha', path: 'big.txt' })).body.result;
    assert.ok(huge.isError);
    assert.match(huge.content[0].text, /too large/);
  } finally { t.close(); }
});

test('share links over MCP need the share scope; an agent can reach link mode but never Public', async () => {
  const { t, ada } = await world();
  try {
    const noShare = (await connect(t, ada, { spaces: ['alpha'], perms: ['read', 'publish'] })).access_token;
    const denied = await call(t, noShare, 'create_share_link', { slug: 'alpha' });
    assert.equal(denied.status, 403);
    assert.match(denied.www, /insufficient_scope.*scope="space:alpha read publish share"/, 'the hint keeps what the grant has');

    const { access_token } = await connect(t, ada, { spaces: ['alpha'], perms: ['read', 'publish', 'share'] });
    const made = await call(t, access_token, 'create_share_link', { slug: 'alpha', label: 'Acme', max_uses: 3 });
    const { link } = made.body.result.structuredContent;
    assert.match(link.url, /\/s\/alpha\/\?key=sfl_/);
    assert.equal(t.store.space('alpha').privacy, 'link');
    const h = { authorization: `Bearer ${access_token}`, 'content-type': 'application/json' };
    const patch = (privacy) => fetch(t.base + '/api/spaces/alpha', { method: 'PATCH', headers: h, body: JSON.stringify({ privacy }) });
    assert.equal((await patch('public')).status, 403, 'Public needs a person');
    assert.equal((await patch('team')).status, 200);
    assert.equal((await patch('link')).status, 200);
    assert.equal(t.store.space('alpha').privacy, 'link');
    assert.ok(t.db.prepare('SELECT disabled_at FROM grants WHERE id = ?').get(link.id).disabled_at, 'an agent switching back does not resume links');
    const again = (await call(t, access_token, 'create_share_link', { slug: 'alpha' })).body.result.structuredContent;
    assert.equal(again.note, undefined, 'already link: nothing switched');
    assert.equal((await patch('team')).status, 200);
    const third = (await call(t, access_token, 'create_share_link', { slug: 'alpha' })).body.result.structuredContent;
    assert.match(third.note, /now "Anyone with the link"\. Only this new link is live; 2 link\(s\) paused earlier stay paused/);
    const timed = (await call(t, access_token, 'create_share_link', { slug: 'alpha', expires_at: '2030-06-01T09:30:00+02:00' })).body.result;
    assert.equal(timed.isError, true, 'more than a year out');
    const week = (await call(t, access_token, 'create_share_link', { slug: 'alpha', expires_in: '7d' })).body.result.structuredContent;
    assert.match(week.link.expires_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    assert.ok(Math.abs(Date.parse(week.link.expires_at) - Date.now() - 7 * 864e5) < 5000);
    const both = (await call(t, access_token, 'create_share_link', { slug: 'alpha', expires_in: '1d', expires_at: week.link.expires_at })).body.result;
    assert.match(both.content[0].text, /not both/);
    const rev = await call(t, access_token, 'revoke_share_link', { slug: 'alpha', id: link.id });
    assert.ok(rev.body.result.structuredContent.link.revoked_at);
    // Out-of-scope space: no link there either.
    const beta = await call(t, access_token, 'create_share_link', { slug: 'beta' });
    assert.equal(beta.status, 403);
    const missing = await call(t, access_token, 'create_share_link', { slug: 'no-such' });
    assert.equal(missing.status, 403, 'a missing space looks like an out-of-scope one');
    assert.equal(missing.body.error.message.replace('no-such', 'beta'), beta.body.error.message);
    const log = t.db.prepare("SELECT actor_kind FROM activity_log WHERE action = 'link.created'").get();
    assert.equal(log.actor_kind, 'oauth');
    // On a Public space the tool says so instead of making a link that can never work.
    assert.equal((await ada.post('/api/spaces/alpha', { privacy: 'public' }, 'PATCH')).status, 200);
    const pub = (await call(t, access_token, 'create_share_link', { slug: 'alpha' })).body.result;
    assert.ok(pub.isError);
    assert.match(pub.content[0].text, /Public/);
  } finally { t.close(); }
});

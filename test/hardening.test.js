// Regression tests for the #215 review findings.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CAS } from '../src/cas.js';
import { boot, client, setupAdmin } from './helpers.js';
import { compilePattern, matchRule, parseHeadersFile } from '../src/routing.js';

test('redirect patterns: placeholders must be whole segments (no ReDoS)', () => {
  assert.throws(() => compilePattern('/:a:b'), /whole path segment/);
  assert.throws(() => compilePattern('/x/:a*'), /whole path segment/);
  assert.throws(() => compilePattern('/:a.html'), /whole path segment/);
  assert.throws(() => compilePattern('/:a/:b/:c/:d/:e/:f/:g/:h/:i'), /more than 8/);
  assert.ok(compilePattern('/blog/:year/:slug/*'));
  const t0 = Date.now();
  matchRule('/:a/:b/:c/:d/:e/:f/:g/:h', '/' + 'a/'.repeat(5000) + 'x', new URLSearchParams());
  assert.ok(Date.now() - t0 < 200);
});

test('_headers cannot set host-scoped headers', () => {
  const { blocks, diagnostics } = parseHeadersFile('/*\n  Strict-Transport-Security: max-age=0\n  Clear-Site-Data: "*"\n  Set-Login: logged-out\n  Permissions-Policy: camera=*\n  X-Ok: 1\n');
  assert.deepEqual(blocks[0].headers, [{ key: 'X-Ok', value: '1' }]);
  assert.equal(diagnostics.length, 4);
});

test('GC keeps a blob that a new write or a fresh version reuses', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fs-cas-'));
  const cas = new CAS(path.join(dir, 'b'), path.join(dir, 't'));
  const old = new Date(Date.now() - 2 * 3600e3);
  const { sha256: a } = await cas.storeBuffer(Buffer.from('a'));
  const { sha256: b } = await cas.storeBuffer(Buffer.from('b'));
  for (const s of [a, b]) fs.utimesSync(cas.path(s), old, old);
  await cas.storeBuffer(Buffer.from('a')); // rewrite of an existing blob refreshes it
  await cas.gc(new Set(), 3600e3, (s) => s === b); // b got referenced after the snapshot
  assert.ok(cas.has(a) && cas.has(b));
  await cas.gc(new Set(), 3600e3);
  assert.ok(cas.has(a) && !cas.has(b));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an invite can be redeemed once, even in parallel', async (x) => {
  const t = await boot(); x.after(t.close);
  const admin = await setupAdmin(t);
  const token = (await (await admin.post('/api/invites', { role: 'admin' })).json()).invite.split('/').pop();
  const accept = (i) => client(t.base).json('/api/invites/accept', { token, name: 'B', email: `b${i}@example.com`, password: 'long enough password' });
  const bad = await client(t.base).json('/api/invites/accept', { token, name: 'B', email: 'x@example.com', password: 'short' });
  assert.equal(bad.status, 400); // a failed attempt releases the claim
  const codes = (await Promise.all([0, 1, 2].map(accept))).map((r) => r.status).sort();
  assert.deepEqual(codes, [201, 400, 400]);
  assert.equal(t.db.prepare('SELECT COUNT(*) c FROM users').get().c, 2);
});

test('first-run setup creates one admin, even in parallel', async (x) => {
  const t = await boot(); x.after(t.close);
  const setup = (i, password = 'long enough password') => client(t.base).json('/api/setup', { name: 'A', email: `a${i}@example.com`, password });
  assert.equal((await setup(9, 'short')).status, 400); // a failed attempt releases the claim
  const codes = (await Promise.all([0, 1, 2].map((i) => setup(i)))).map((r) => r.status).sort();
  assert.deepEqual(codes, [201, 403, 403]);
  assert.equal(t.db.prepare('SELECT COUNT(*) c FROM users').get().c, 1);
});

test('login throttle: per account+IP, counted before verifying, proxy-aware', async (x) => {
  const t = await boot({ trustProxy: true }); x.after(t.close);
  await setupAdmin(t);
  const login = (email, ip, password = 'wrong password') => client(t.base).json('/api/login', { email, password }, 'POST', { 'x-forwarded-for': `1.1.1.1, ${ip}` });
  const codes = (await Promise.all(Array.from({ length: 12 }, () => login('ada@example.com', '9.9.9.9')))).map((r) => r.status);
  assert.equal(codes.filter((c) => c === 429).length, 2, String(codes)); // parallel attempts are all counted
  assert.equal((await login('ada@example.com', '9.9.9.9', 'correct horse battery')).status, 429);
  assert.equal((await login('ada@example.com', '8.8.8.8', 'correct horse battery')).status, 200); // other clients unaffected
});

test('unauthenticated POSTs need same-origin Fetch Metadata or a same-host Origin (login CSRF)', async (x) => {
  const t = await boot(); x.after(t.close);
  const host = new URL(t.base).host;
  const setup = (headers) => client(t.base).json('/api/setup', { name: 'A', email: 'a@example.com', password: 'long enough password' }, 'POST', headers);
  for (const h of [{ 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': '' }, { 'sec-fetch-site': '', origin: 'https://evil.example' }]) assert.equal((await setup(h)).status, 403, JSON.stringify(h));
  assert.equal((await setup({ 'sec-fetch-site': '', origin: `http://${host}` })).status, 201);
});

// The CIMD fetcher against a real local HTTPS server (issue #214 section 6: SSRF guard).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import { fetchJson, isPrivateIp } from '../src/ssrf.js';

const fx = (f) => fs.readFileSync(new URL(`./fixtures/${f}`, import.meta.url));
// Test-only: resolve cimd.test to the local server and trust its self-signed cert.
const tls = (port) => ({ ca: fx('cimd-test.crt'), lookup: (h, o, cb) => (o?.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4)), port });

async function serve(t, handler) {
  const s = https.createServer({ key: fx('cimd-test.key'), cert: fx('cimd-test.crt') }, handler);
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  t.after(() => { s.closeAllConnections(); s.close(); });
  const { port } = s.address();
  return (opts = {}) => fetchJson(`https://cimd.test:${port}/c.json`, { tls: tls(port), ...opts });
}

test('fetches a small JSON document', async (t) => {
  const get = await serve(t, (q, r) => r.end('{"ok":true}'));
  assert.deepEqual(await get(), { ok: true });
});

test('a host trickling bytes hits the total deadline, not just an idle timer', async (t) => {
  const get = await serve(t, (q, r) => { r.writeHead(200); const i = setInterval(() => r.write(' '), 100); r.on('close', () => clearInterval(i)); });
  const t0 = Date.now();
  await assert.rejects(get({ timeoutMs: 500 }), /timed out/);
  assert.ok(Date.now() - t0 < 1500);
});

test('documents over the size limit are refused', async (t) => {
  const get = await serve(t, (q, r) => r.end('"' + 'x'.repeat(100 * 1024) + '"'));
  await assert.rejects(get(), /too large/);
});

test('redirects are not followed', async (t) => {
  const get = await serve(t, (q, r) => { r.writeHead(302, { location: 'https://127.0.0.1/' }); r.end(); });
  await assert.rejects(get(), /HTTP 302/);
});

test('private IPv4, IPv6, IPv4-mapped and NAT64/6to4 addresses are refused before connecting', async () => {
  for (const host of ['127.0.0.1', '[::1]', '[fd00::1]', '[fe80::1]', '[::ffff:127.0.0.1]', '[::ffff:7f00:1]', '[64:ff9b::a00:1]', '[64:ff9b:1::1]']) {
    await assert.rejects(fetchJson(`https://${host}/c.json`), /Blocked private address/, host);
  }
  for (const ip of ['64:ff9b:1::1']) assert.ok(isPrivateIp(ip), ip);
  assert.ok(!isPrivateIp('2606:4700::1111'));
});

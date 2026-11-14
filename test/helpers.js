import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../src/server.js';

export async function boot(overrides = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'greenroom-'));
  const app = createApp({ dataDir, port: 0, ...overrides });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const close = () => { app.server.close(); app.db.close(); fs.rmSync(dataDir, { recursive: true, force: true }); };
  return { ...app, base, close };
}

/** Tiny cookie-jar client. Sends Sec-Fetch-Site like a same-origin browser unless told otherwise. */
export function client(base) {
  const jar = new Map();
  const c = {
    jar,
    async fetch(p, { headers = {}, ...init } = {}) {
      const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
      const res = await fetch(base + p, { redirect: 'manual', ...init, headers: { 'sec-fetch-site': 'same-origin', ...(cookie && { cookie }), ...headers } });
      for (const sc of res.headers.getSetCookie()) {
        const [kv, ...attrs] = sc.split(';');
        const i = kv.indexOf('=');
        if (attrs.some((a) => /max-age=0/i.test(a))) jar.delete(kv.slice(0, i)); else jar.set(kv.slice(0, i), kv.slice(i + 1));
      }
      return res;
    },
    async json(p, body, method = 'POST', headers = {}) {
      return c.fetch(p, { method, body: body && JSON.stringify(body), headers: { 'content-type': 'application/json', ...headers } });
    },
  };
  return c;
}

export async function setupAdmin(t) {
  const c = client(t.base);
  const r = await c.json('/api/setup', { name: 'Ada', email: 'ada@example.com', password: 'correct horse battery' });
  if (r.status !== 201) throw new Error('setup failed ' + (await r.text()));
  const csrf = t.db.prepare('SELECT csrf_token FROM sessions').get().csrf_token;
  c.csrf = csrf;
  c.post = (p, body, method = 'POST') => c.json(p, body, method, { 'x-csrf-token': csrf });
  return c;
}

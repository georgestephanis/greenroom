// Builds a read-only tour of the dashboard as static HTML (for GitHub Pages).
// It boots a throwaway greenroom, fills it with sample data through the real API and MCP endpoint,
// then saves each page with links rewritten to relative paths. Forms are left in place; tour.js
// stops them from submitting.
//
//   node scripts/tour/build.js [outDir]    (default: _tour)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../../src/server.js';
import { APP_CSS } from '../../src/dashboard.js';

const here = import.meta.dirname;
const out = path.resolve(process.argv[2] || '_tour');
const sample = (f) => fs.readFileSync(path.join(here, 'sample', f), 'utf8');
const PUBLIC = 'https://greenroom.example.com';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'greenroom-tour-'));
const app = createApp({ dataDir, port: 0, publicUrl: PUBLIC });
await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${app.server.address().port}`;

function client() {
  const jar = new Map();
  const c = {
    async fetch(p, { headers = {}, ...init } = {}) {
      const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
      const res = await fetch(base + p, { redirect: 'manual', ...init, headers: { 'sec-fetch-site': 'same-origin', ...(cookie && { cookie }), ...headers } });
      for (const sc of res.headers.getSetCookie()) { const kv = sc.split(';')[0]; const i = kv.indexOf('='); jar.set(kv.slice(0, i), kv.slice(i + 1)); }
      return res;
    },
    async send(p, body, method = 'POST') {
      const r = await c.fetch(p, { method, body: JSON.stringify(body), headers: { 'content-type': 'application/json', ...(c.csrf && { 'x-csrf-token': c.csrf }) } });
      if (r.status >= 300) throw new Error(`${method} ${p}: ${r.status} ${await r.text()}`);
      return r.json();
    },
  };
  return c;
}
const csrfFor = (email) => app.db.prepare('SELECT s.csrf_token FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = ? ORDER BY s.created_at DESC').get(email).csrf_token;

try {
  // People: Ada (admin) and Ben (member).
  const ada = client();
  await ada.send('/api/setup', { name: 'Ada', email: 'ada@example.com', password: 'correct horse battery' });
  ada.csrf = csrfFor('ada@example.com');
  const { invite } = await ada.send('/api/invites', { role: 'member' });
  const ben = client();
  await ben.send('/api/invites/accept', { token: invite.split('/').pop(), name: 'Ben', email: 'ben@example.com', password: 'ben password 1234' });
  ben.csrf = csrfFor('ben@example.com');
  await ada.send('/api/invites', { role: 'member' }); // one open invite, so the Team page shows one

  // An agent token, used over MCP so history says "Claude (via Ada)".
  const { token } = await ada.send('/api/tokens', { name: 'Claude', create: true, perms: ['read', 'publish', 'share'] });
  let id = 0;
  const mcp = async (name, args) => {
    const r = await fetch(base + '/mcp', { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } }) });
    const j = await r.json();
    if (j.error || j.result?.isError) throw new Error(`MCP ${name}: ${JSON.stringify(j)}`);
  };
  const simple = (title, body) => `<!doctype html><meta charset="utf-8"><title>${title}</title><link rel="stylesheet" href="style.css"><main><p class="eyebrow">Acme Co</p><h1>${title}</h1><p>${body}</p></main>`;
  const sites = {
    'churn-dashboard': { 'index.html': simple('Churn dashboard', 'Weekly cohort churn, refreshed every Monday.'), 'style.css': sample('style.css') },
    'onboarding-prototype': { 'index.html': simple('Welcome aboard', 'Step 1 of 3: tell us about your team.'), 'style.css': sample('style.css') },
    'q3-board-report': { 'index.html': sample('v2.html'), 'chart.svg': sample('chart.svg'), 'style.css': sample('style.css') },
  };
  const files = (o) => Object.entries(o).map(([p, content]) => ({ path: p, content }));
  await mcp('create_space', { name: 'Churn dashboard', slug: 'churn-dashboard' });
  await mcp('publish', { slug: 'churn-dashboard', message: 'Weekly refresh', files: files(sites['churn-dashboard']) });
  await mcp('create_space', { name: 'Onboarding prototype', slug: 'onboarding-prototype' });
  await mcp('publish', { slug: 'onboarding-prototype', message: 'Clickable prototype', files: files(sites['onboarding-prototype']) });
  await mcp('create_space', { name: 'Q3 board report', slug: 'q3-board-report' });
  await mcp('publish', { slug: 'q3-board-report', message: 'First draft', files: files({ 'index.html': sample('v1.html'), 'style.css': sample('style.css') }) });
  await mcp('publish', { slug: 'q3-board-report', base: 'live', message: 'Add revenue chart', files: files({ 'index.html': sample('v2.html'), 'chart.svg': sample('chart.svg') }) });
  await ben.send('/api/spaces/onboarding-prototype/versions', { base: 'live', message: 'Fix the step count', files: files(sites['onboarding-prototype']) });
  await ada.send('/api/spaces/q3-board-report/links', { label: 'Acme — CFO', expires_in: '7d', password: 'board-q3-2026', max_uses: 5 });
  await ada.send('/api/spaces/churn-dashboard', { privacy: 'public' }, 'PATCH');

  // Pages to save: [server path, file in the tour].
  const pages = [
    ['/', 'index.html'],
    ...Object.keys(sites).map((s) => [`/spaces/${s}`, `spaces/${s}/index.html`]),
    ['/access', 'access/index.html'],
    ['/team', 'team/index.html'],
    ['/instance', 'instance/index.html'],
    ['/account', 'account/index.html'],
  ];
  // Fetch every page, adding each "Diff vs" link the space pages show.
  const raw = new Map();
  for (let i = 0; i < pages.length; i++) {
    const [p] = pages[i];
    const r = await ada.fetch(p);
    if (r.status !== 200) throw new Error(`GET ${p}: ${r.status}`);
    const html = await r.text();
    raw.set(p, html);
    for (const m of html.matchAll(/href="(\/spaces\/([^/"]+)\/diff\?from=(\d+)&(?:amp;)?to=(\d+))"/g)) {
      const diff = m[1].replace(/&amp;/g, '&');
      if (!pages.some(([q]) => q === diff)) pages.push([diff, `spaces/${m[2]}/diff-${m[3]}-${m[4]}.html`]);
    }
  }
  const fileFor = new Map(pages);
  fs.rmSync(out, { recursive: true, force: true });

  const rewrite = (html, file) => {
    const rel = (target) => path.posix.relative(path.posix.dirname(file), target) || path.posix.basename(target);
    const map = (url) => {
      const u = url.replace(/&amp;/g, '&');
      if (u === '/assets/app.css') return rel('assets/app.css');
      if (u === '/assets/app.js') return rel('assets/tour.js');
      const hash = u.includes('#') ? u.slice(u.indexOf('#')) : '';
      const bare = u.slice(0, u.length - hash.length);
      if (fileFor.has(bare)) return rel(fileFor.get(bare)) + hash;
      const s = /^\/s\/([^/]+)\/(.*)$/.exec(bare);
      if (s && sites[s[1]]) return rel(`s/${s[1]}/${s[2] || 'index.html'}`);
      return null;
    };
    return html
      .replace(/<meta name="csrf"[^>]*>/, '')
      .replace(/<input type="hidden" name="_csrf"[^>]*>/g, '')
      .replace(/\b(href|src)="(\/[^"]*)"/g, (all, attr, url) => {
        const to = map(url);
        if (to) return `${attr}="${to}"`;
        return attr === 'href' ? `href="#" data-tour-off title="Not part of the tour"` : all;
      })
      .replace('</head>', `<link rel="stylesheet" href="${rel('assets/tour.css')}"></head>`)
      .replaceAll(base, PUBLIC);
  };

  for (const [p, file] of pages) {
    const dest = path.join(out, file);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, rewrite(raw.get(p), file));
  }
  for (const [slug, site] of Object.entries(sites)) {
    for (const [f, content] of Object.entries(site)) {
      const dest = path.join(out, 's', slug, f);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, content);
    }
  }
  fs.mkdirSync(path.join(out, 'assets'), { recursive: true });
  fs.writeFileSync(path.join(out, 'assets/app.css'), APP_CSS);
  for (const f of ['tour.js', 'tour.css']) fs.copyFileSync(path.join(here, f), path.join(out, 'assets', f));
  fs.writeFileSync(path.join(out, '.nojekyll'), '');
  console.log(`Tour written to ${out} (${pages.length} pages)`);
} finally {
  app.server.close();
  app.db.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
}

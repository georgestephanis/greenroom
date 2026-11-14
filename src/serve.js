// Serving a space under /s/{slug}/. Every response that leaves this module carries the sandbox
// headers (rule 1), whatever its status or content type.
import { matchRule, substituteDestination, computeHeadersForPath } from './routing.js';
import { parseCookies, SESSION_COOKIE } from './auth.js';
import {
  applySpaceHeaders, filterTenantHeaders, viewerCookieName, signViewer, verifyViewer, viewerSetCookie,
  signDocToken, injectDocToken, isDocumentRequest,
} from './security.js';
import { esc } from './util.js';

const HIDDEN = new Set(['_redirects', '_headers']);

function send(res, status, body, headers = {}) {
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.statusCode = status;
  res.end(body);
}
const page = (title, msg) =>
  `<!doctype html><meta charset="utf-8"><title>${esc(title)}</title><body style="font:16px system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>${esc(title)}</h1><p>${esc(msg)}</p>`;

export function createSpaceHandler({ store, auth, config }) {
  return async function handleSpace(req, res, url) {
    const m = /^\/s\/([^/]+)(\/.*)?$/.exec(url.pathname);
    const method = req.method;
    const slug = m ? m[1] : '';
    const space = m ? store.space(slug) : null;
    applySpaceHeaders(res, { noindex: space ? !!space.noindex : true });
    res.setHeader('Vary', 'Cookie');

    if (method !== 'GET' && method !== 'HEAD') return send(res, 405, 'Method not allowed', { Allow: 'GET, HEAD' });
    if (!m || !space) return send(res, 404, page('Not found', 'There is no space here.'), { 'Content-Type': 'text/html; charset=utf-8' });
    if (!m[2]) return send(res, 308, '', { Location: `/s/${slug}/${url.search}` });

    // ---- who may view? every mode ends at the same space-bound viewer cookie (rule 6) ----
    const cookies = parseCookies(req.headers.cookie);
    if (space.privacy !== 'public') {
      const viewer = verifyViewer(config.secret, space, cookies[viewerCookieName(space)]);
      let ok = false;
      // Bound to the dashboard session that minted it: logout or a removed member ends access.
      if (viewer && viewer.kind === 'team') ok = !!auth.sessionUser(viewer.subject);
      if (!ok) {
        // The Strict dashboard cookie only arrives on same-site navigations; use it to mint a viewer cookie.
        const s = auth.sessionFromCookie(cookies[SESSION_COOKIE]);
        const u = s && auth.activeUser(s.user_id);
        if (u) {
          const signed = signViewer(config.secret, space, s.id, config.viewerMinutes * 60e3);
          res.setHeader('Set-Cookie', viewerSetCookie(space, signed));
          ok = true;
        }
      }
      if (!ok) {
        const doc = isDocumentRequest(req) || (req.headers.accept || '').includes('text/html');
        if (doc) return send(res, 302, '', { Location: `/login?next=${encodeURIComponent(url.pathname + url.search)}`, 'Cache-Control': 'no-store' });
        return send(res, 401, 'Sign in required', { 'Cache-Control': 'no-store' });
      }
    }
    const cacheControl = space.privacy === 'public' ? 'public, max-age=0, must-revalidate' : 'private, no-cache';

    // ---- resolve against the live manifest ----
    if (!space.live_version_id) return send(res, 404, page('Nothing published yet', 'This space has no versions.'), { 'Content-Type': 'text/html; charset=utf-8' });
    const vid = space.live_version_id;
    const base = `/s/${slug}`;
    let rel;
    try { rel = decodeURIComponent(m[2]); } catch { return send(res, 400, 'Bad request'); }
    if (rel.includes('\0') || rel.split('/').includes('..')) return send(res, 400, 'Bad request');

    const version = store.db.prepare('SELECT routing_json FROM versions WHERE id = ?').get(vid);
    const routing = JSON.parse(version.routing_json || '{}');
    const lookup = (p) => (HIDDEN.has(p) ? undefined : store.file(vid, p));

    const find = () => {
      let p = rel.replace(/^\/+/, '');
      if (p === '' || p.endsWith('/')) return { file: lookup(p + 'index.html') };
      const exact = lookup(p) || lookup(p + '.html');
      if (exact) return { file: exact };
      const idx = lookup(p + '/index.html');
      if (idx) return { redirect: `${base}/${p}/${url.search}` };
      return {};
    };

    const applyRules = (force) => {
      for (const r of routing.redirects || []) {
        if (!!r.force !== force) continue;
        const { matched, params } = matchRule(r.source, rel, url.searchParams, r.query);
        if (!matched) continue;
        let dest = substituteDestination(r.destination, params);
        const local = dest.startsWith('/') && !dest.startsWith('//');
        if (r.status === 200) {
          if (!local) continue; // no proxying in core
          return { rewrite: dest.split('?')[0].replace(/^\/+/, '') };
        }
        if (r.status === 404) return { notFound: true };
        if (local) dest = base + dest;
        else if (!/^https?:\/\//i.test(dest)) continue;
        return { redirect: dest, status: r.status };
      }
      return null;
    };

    let status = 200, file, hit = applyRules(true) || null;
    if (!hit) {
      const f = find();
      if (f.file) file = f.file;
      else if (f.redirect) hit = { redirect: f.redirect, status: 308 };
      else hit = applyRules(false);
    }
    if (hit?.redirect) return send(res, hit.status ?? 302, '', { Location: hit.redirect, 'Cache-Control': 'no-cache' });
    if (hit?.rewrite !== undefined) file = lookup(hit.rewrite) || lookup(hit.rewrite + '/index.html');
    if (!file) {
      const nf = lookup('404.html');
      status = 404;
      if (!nf) return send(res, 404, page('Not found', 'No such file in this space.'), { 'Content-Type': 'text/html; charset=utf-8' });
      file = nf;
    }

    // ---- tenant headers (rule 2: reserved ones never get through, even if a stale manifest has them) ----
    const { kept } = filterTenantHeaders(computeHeadersForPath(routing.headers || [], '/' + rel.replace(/^\/+/, '')));
    for (const [k, v] of Object.entries(kept)) res.setHeader(k, v);
    applySpaceHeaders(res, { noindex: !!space.noindex }); // re-assert: ours always win
    if (!space.noindex) res.removeHeader('X-Robots-Tag');
    res.setHeader('Content-Type', file.content_type);
    res.setHeader('Cache-Control', cacheControl);
    res.setHeader('Accept-Ranges', 'bytes');

    // Documents of spaces with the sqlite plugin on get a per-document token (rule 7).
    const plugins = JSON.parse(space.plugins_json || '[]');
    if (status === 200 && plugins.includes('sqlite') && file.content_type.startsWith('text/html') && isDocumentRequest(req)) {
      const html = injectDocToken((await store.cas.read(file.sha256)).toString('utf8'), signDocToken(config.secret, space));
      res.setHeader('Cache-Control', 'no-store');
      return send(res, status, method === 'HEAD' ? '' : html, { 'Content-Length': Buffer.byteLength(html) });
    }

    const etag = `"${file.sha256}"`;
    res.setHeader('ETag', etag);
    if (status === 200 && req.headers['if-none-match'] === etag) return send(res, 304, '');

    let start = 0, end = file.size - 1;
    const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (range && status === 200 && (range[1] || range[2])) {
      if (range[1] === '') { start = Math.max(0, file.size - Number(range[2])); }
      else { start = Number(range[1]); if (range[2]) end = Math.min(end, Number(range[2])); }
      if (start > end || start >= file.size) return send(res, 416, '', { 'Content-Range': `bytes */${file.size}` });
      res.statusCode = 206;
      res.setHeader('Content-Range', `bytes ${start}-${end}/${file.size}`);
    } else {
      res.statusCode = status;
    }
    // Content-Length comes from the blob actually on disk, never from a declared value.
    const onDisk = store.cas.size(file.sha256);
    if (onDisk === null) return send(res, 500, 'Blob missing');
    if (res.statusCode === 200 || res.statusCode === 404) end = onDisk - 1;
    res.setHeader('Content-Length', Math.max(0, end - start + 1));
    if (method === 'HEAD' || file.size === 0) return res.end();
    store.cas.stream(file.sha256, { start, end }).on('error', () => res.destroy()).pipe(res);
  };
}

// One-way move of spaces to Spacefast, or to a homefast instance, over its public API (issue #214, amendment:
// leaving is a supported path). Nothing here is changed or deleted. The API token lives only in this job's
// closure: never stored, logged or shown again.
import { request } from './ssrf.js';
import { now } from './util.js';
import { GENERATOR } from './bundle.js';

const ACCESS = { team: 'private', link: 'private', public: 'public' };
export const NOT_CARRIED = ['People, roles and access tokens', 'Share links and passwords', 'Plugin data and settings (including the watermark)', 'Original publish dates and authors (each version keeps its message)'];

/** API root from what an admin typed: `https://api.spacefast.com`, with or without a trailing `/v1`. */
export function apiRoot(input) {
  let u;
  try { u = new URL(String(input || '').trim()); } catch { throw Object.assign(new Error('Enter the API address, like https://api.spacefast.com'), { status: 400 }); }
  if (u.protocol !== 'https:') throw Object.assign(new Error('The API address must start with https://'), { status: 400 });
  return new URL(u.pathname.replace(/\/+$/, '').replace(/\/v1$/, '') + '/', u.origin);
}

// ponytail: one job at a time, held in memory. A restart mid-move means starting again; spaces already
// moved come back as slug conflicts and are reported, not overwritten.
export function startMigration({ store, cas, tls = {} }, { url, token, slugs, history }) {
  const root = apiRoot(url);
  if (!/^\S{8,}$/.test(String(token || ''))) throw Object.assign(new Error('Paste an API key from the target'), { status: 400 });
  const spaces = slugs.map((s) => store.space(s)).filter(Boolean);
  if (!spaces.length) throw Object.assign(new Error('Pick at least one space'), { status: 400 });
  const job = { target: root.href, history: !!history, startedAt: now(), done: false, notCarried: NOT_CARRIED,
    spaces: spaces.map((s) => ({ slug: s.slug, name: s.name, status: 'waiting', versions: 0, note: '' })) };

  const resolve = (p) => (/^https:/i.test(p) ? new URL(p) : new URL(String(p).replace(/^\/+/, ''), root));
  async function api(method, path, body, headers = {}) {
    const r = await request(resolve(path), { method, tls, maxBytes: 8 * 1024 * 1024, timeoutMs: 5 * 60e3, what: 'Target API',
      headers: { authorization: `Bearer ${token}`, accept: 'application/json', 'content-type': 'application/json', ...headers }, body: body && JSON.stringify(body) });
    let j = null;
    try { j = JSON.parse(r.body); } catch {}
    if (r.status >= 300) {
      const msg = j?.detail || j?.title || j?.error?.message || (typeof j?.error === 'string' && j.error) || `HTTP ${r.status}`;
      throw Object.assign(new Error(`${method} ${path}: ${msg}`), { code: j?.code || j?.error?.code });
    }
    return { status: r.status, data: j?.data ?? j };
  }
  async function put(t, byPath) {
    const f = byPath.get(t.path);
    if (!f) throw new Error(`Target asked for a file this version doesn't have: ${t.path}`);
    if (t.body) throw new Error(`Target wants a form upload for ${t.path}; greenroom only sends raw bytes`);
    const u = resolve(t.url), own = u.origin === root.origin;
    const headers = { ...(own && { authorization: `Bearer ${token}` }), ...t.headers, 'content-length': String(f.size) };
    const r = await request(u, { method: t.method || 'PUT', tls, headers, body: cas.stream(f.sha256), timeoutMs: 30 * 60e3, what: 'Upload' });
    if (r.status >= 300) throw new Error(`Upload of ${t.path} failed: HTTP ${r.status}`);
  }

  async function move(space, row) {
    const ready = store.versions(space.id).filter((v) => v.status === 'ready').reverse(); // oldest first
    const live = ready.find((v) => v.id === space.live_version_id);
    const todo = history ? [...ready.filter((v) => v !== live), ...(live ? [live] : [])] : live ? [live] : [];
    if (!todo.length) { row.status = 'skipped'; row.note = 'Nothing published yet'; return; }
    let access = ACCESS[space.privacy] || 'private', made;
    try { made = await api('POST', 'v1/spaces', { slug: space.slug, title: space.name, access }); }
    catch (e) {
      if (e.code !== 'team_private_spaces_only' || access !== 'public') throw e;
      made = await api('POST', 'v1/spaces', { slug: space.slug, title: space.name, access: access = 'private' });
      row.note = 'Made private: the target team only allows private spaces. ';
    }
    // homefast answers 200 with the existing space for a taken slug; never publish over someone's site.
    if (made.status === 200) { row.status = 'skipped'; row.note += 'A space with this slug already exists on the target'; return; }
    const id = made.data?.space?.id ?? made.data?.id;
    if (!id) throw new Error('Target did not return a space id');
    row.status = 'moving';
    for (const v of todo) {
      const files = store.manifest(v.id).map((f) => ({ path: f.path, size: f.size, sha256: f.sha256, contentType: f.content_type }));
      const byPath = new Map(files.map((f) => [f.path, f]));
      let { data } = await api('POST', `v1/spaces/${id}/versions`, { files, publishMode: 'snapshot',
        source: { kind: 'import', client: `greenroom/${GENERATOR.version}`, message: v.message || `greenroom version ${v.number}` } });
      const versionId = data?.versionId;
      // Targets come in pages; refresh hands out the next page until nothing is left to upload.
      for (let pages = 0; data?.upload; pages++) {
        if (pages > files.length + 1) throw new Error('Target kept asking for uploads');
        for (const t of data.upload.targets || []) await put(t, byPath);
        if (!data.upload.links?.refresh) break;
        ({ data } = await api('POST', data.upload.links.refresh));
      }
      if (versionId) {
        // channel null finalizes without going live; only the version that is live here goes live there.
        const { data: f } = await api('POST', `v1/spaces/${id}/versions/${versionId}/finalize`, v === live ? {} : { channel: null }, { 'idempotency-key': `greenroom-${v.id}` });
        if (f?.status === 'failed') throw new Error(`Version ${v.number}: ${f.failureMessage || 'the target could not finish it'}`);
      } else if (v === live) row.note += 'The target saw no changes in the live version; check which version is live there. ';
      row.versions++;
    }
    row.status = 'done';
    row.url = made.data?.space?.url || made.data?.url || '';
  }

  job.promise = (async () => {
    for (const [i, space] of spaces.entries()) {
      const row = job.spaces[i];
      try { await move(space, row); } catch (e) { row.status = 'failed'; row.note += e.message; }
    }
  })().finally(() => { job.done = true; job.finishedAt = now(); });
  return job;
}

/** What the page and API show: everything but the promise (the token was never on the job). */
export const jobView = (j) => j && { target: j.target, history: j.history, startedAt: j.startedAt, finishedAt: j.finishedAt, done: j.done, spaces: j.spaces, notCarried: j.notCarried };

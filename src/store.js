// Spaces, versions, manifests. A version row is a "commit", a manifest is a "tree", a CAS blob is a
// "file" (issue #214 section 5). Versions are immutable; "live" is a pointer.
import { tx } from './db.js';
import { httpErr, authorName, authorId } from './auth.js';
import { newId, now, SLUG_RE, slugify, cleanPath, contentType } from './util.js';
import { parseRedirectsFile, parseHeadersFile } from './routing.js';

const META_FILES = 256 * 1024;

export class Store {
  constructor(db, cas, config) {
    this.db = db;
    this.cas = cas;
    this.config = config;
  }

  // ---- activity ----
  log(cred, action, spaceId, detail = {}, resource = {}) {
    this.db.prepare(
      'INSERT INTO activity_log (space_id,actor_kind,actor_id,action,resource_type,resource_id,detail_json,created_at) VALUES (?,?,?,?,?,?,?,?)',
    ).run(spaceId ?? null, cred?.type ?? 'system', cred ? authorId(cred) : null, action, resource.type ?? null, resource.id ?? null, JSON.stringify(detail), now());
  }

  // ---- spaces ----
  space(slug) { return this.db.prepare('SELECT * FROM spaces WHERE slug = ? AND archived_at IS NULL').get(slug); }
  spaceById(id) { return this.db.prepare('SELECT * FROM spaces WHERE id = ?').get(id); }

  listSpaces(slugs = '*') {
    const rows = this.db.prepare(
      `SELECT s.*, v.number AS live_number, v.author_name AS live_author, v.created_at AS live_at, v.total_files, v.total_bytes
       FROM spaces s LEFT JOIN versions v ON v.id = s.live_version_id
       WHERE s.archived_at IS NULL ORDER BY COALESCE(v.created_at, s.created_at) DESC`,
    ).all();
    return slugs === '*' ? rows : rows.filter((r) => slugs.includes(r.slug));
  }

  createSpace(cred, { name, slug }) {
    name = String(name || '').trim();
    if (!name) throw httpErr(400, 'name is required');
    slug = String(slug || slugify(name));
    if (!SLUG_RE.test(slug)) throw httpErr(400, 'slug must be lowercase letters, digits and dashes');
    if (this.db.prepare('SELECT 1 FROM spaces WHERE slug = ?').get(slug)) throw httpErr(409, 'That slug is taken');
    const id = newId('spc'), t = now();
    this.db.prepare('INSERT INTO spaces (id,slug,name,owner_id,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(id, slug, name, cred.userId, t, t);
    this.log(cred, 'space.created', id, { slug, name }, { type: 'space', id });
    return this.spaceById(id);
  }

  updateSpace(cred, space, patch) {
    const sets = [], vals = [];
    if (patch.name !== undefined) {
      if (!String(patch.name).trim()) throw httpErr(400, 'name is required');
      sets.push('name = ?'); vals.push(String(patch.name).trim());
    }
    if (patch.slug !== undefined && patch.slug !== space.slug) {
      if (!SLUG_RE.test(patch.slug)) throw httpErr(400, 'invalid slug');
      if (this.db.prepare('SELECT 1 FROM spaces WHERE slug = ?').get(patch.slug)) throw httpErr(409, 'That slug is taken');
      sets.push('slug = ?'); vals.push(patch.slug);
    }
    if (patch.privacy !== undefined) {
      // 'link' arrives with M3; agents may never make a space public (checked by the caller via requireSession).
      if (!['team', 'public'].includes(patch.privacy)) throw httpErr(400, 'privacy must be team or public');
      sets.push('privacy = ?'); vals.push(patch.privacy);
    }
    if (patch.noindex !== undefined) { sets.push('noindex = ?'); vals.push(patch.noindex ? 1 : 0); }
    if (!sets.length) return space;
    sets.push('updated_at = ?'); vals.push(now());
    this.db.prepare(`UPDATE spaces SET ${sets.join(', ')} WHERE id = ?`).run(...vals, space.id);
    this.log(cred, 'space.updated', space.id, patch, { type: 'space', id: space.id });
    return this.spaceById(space.id);
  }

  deleteSpace(cred, space) {
    this.log(cred, 'space.deleted', null, { slug: space.slug, id: space.id });
    this.db.prepare('DELETE FROM spaces WHERE id = ?').run(space.id); // blobs reclaimed by lazy GC
    this.maybeGc();
  }

  // ---- manifests / versions ----
  version(spaceId, number) { return this.db.prepare('SELECT * FROM versions WHERE space_id = ? AND number = ?').get(spaceId, number); }
  versions(spaceId) { return this.db.prepare('SELECT * FROM versions WHERE space_id = ? ORDER BY number DESC').all(spaceId); }
  manifest(versionId) {
    return this.db.prepare('SELECT path, sha256, size, content_type FROM manifest_files WHERE version_id = ? ORDER BY path').all(versionId);
  }
  file(versionId, path) {
    return this.db.prepare('SELECT path, sha256, size, content_type FROM manifest_files WHERE version_id = ? AND path = ?').get(versionId, path);
  }
  hasPrefix(versionId, prefix) {
    return !!this.db.prepare('SELECT 1 FROM manifest_files WHERE version_id = ? AND path >= ? AND path < ? LIMIT 1').get(versionId, prefix, prefix + '￿');
  }
  /** base: undefined => full tree; 'live' | number => patch on that version. */
  resolveBase(space, base) {
    if (base === undefined || base === null) return null;
    const v = base === 'live' ? (space.live_version_id && this.db.prepare('SELECT * FROM versions WHERE id = ?').get(space.live_version_id)) : this.version(space.id, Number(base));
    if (!v && base !== 'live') throw httpErr(404, `No such base version: ${base}`);
    return v || null;
  }

  /**
   * Publish: `files` [{path, content | base64 | sha256}], `remove` [paths]. Blobs already in CAS can be
   * referenced by hash. Returns the new version.
   */
  async publish(cred, space, { files = [], remove = [], base, message, source = 'api' }) {
    const entries = new Map();
    const baseV = this.resolveBase(space, base);
    if (baseV) for (const f of this.manifest(baseV.id)) entries.set(f.path, f);
    for (const p of remove) {
      const c = cleanPath(p);
      if (c) entries.delete(c);
    }
    for (const f of files) {
      const p = cleanPath(f.path);
      if (!p) throw httpErr(400, `Invalid path: ${f.path}`);
      let stored;
      if (typeof f.content === 'string') stored = await this.cas.storeBuffer(Buffer.from(f.content, 'utf8'));
      else if (typeof f.base64 === 'string') stored = await this.cas.storeBuffer(Buffer.from(f.base64, 'base64'));
      else if (typeof f.sha256 === 'string' && this.cas.touch(f.sha256)) stored = { sha256: f.sha256.toLowerCase(), size: this.cas.size(f.sha256) };
      else throw httpErr(400, `File needs content, base64 or a known sha256: ${f.path}`);
      if (stored.size > this.config.maxFileBytes) throw httpErr(413, `File too large: ${p}`);
      entries.set(p, { path: p, sha256: stored.sha256, size: stored.size, content_type: contentType(p) });
    }
    return this.createVersion(cred, space, entries, { message, source, parent: baseV ?? undefined });
  }

  /** `entries`: Map(path -> {sha256,size,content_type}). Immutable once written. */
  async createVersion(cred, space, entries, { message, source = 'api', parent } = {}) {
    if (!entries.size) throw httpErr(400, 'A version needs at least one file');
    const list = [...entries.values()];
    const total = list.reduce((n, f) => n + f.size, 0);
    if (total > this.config.maxSpaceBytes) throw httpErr(413, 'Space size limit exceeded');
    const routing = await this.#compileRouting(entries);
    const live = space.live_version_id ? this.db.prepare('SELECT * FROM versions WHERE id = ?').get(space.live_version_id) : null;
    const parentId = (parent ?? live)?.id ?? null;
    const id = newId('ver'), t = now();
    const number = tx(this.db, () => {
      const n = (this.db.prepare('SELECT MAX(number) m FROM versions WHERE space_id = ?').get(space.id).m ?? 0) + 1;
      this.db.prepare(
        `INSERT INTO versions (id,space_id,number,status,routing_json,total_files,total_bytes,created_at,finalized_at,
          parent_version_id,author_credential_id,author_name,message,source,warnings_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      ).run(id, space.id, n, 'ready', JSON.stringify({ redirects: routing.redirects, headers: routing.headers }), list.length, total, t, t,
        parentId, authorId(cred), authorName(cred), message ? String(message).slice(0, 500) : null, source, JSON.stringify(routing.warnings));
      const ins = this.db.prepare('INSERT INTO manifest_files (version_id,space_id,path,sha256,size,declared_size,content_type) VALUES (?,?,?,?,?,?,?)');
      for (const f of list) ins.run(id, space.id, f.path, f.sha256, f.size, f.size, f.content_type);
      this.db.prepare('UPDATE spaces SET live_version_id = ?, updated_at = ? WHERE id = ?').run(id, t, space.id);
      return n;
    });
    this.log(cred, 'version.created', space.id, { number, source, files: list.length }, { type: 'version', id });
    this.maybeGc();
    return { ...this.version(space.id, number), warnings: routing.warnings };
  }

  // Rule 2: tenant _headers / _redirects are parsed at finalize; reserved headers are dropped with a warning.
  async #compileRouting(entries) {
    const warnings = [];
    let redirects = [], headers = [];
    const red = entries.get('_redirects'), hdr = entries.get('_headers');
    if (red && red.size <= META_FILES) {
      const r = parseRedirectsFile((await this.cas.read(red.sha256)).toString('utf8'));
      redirects = r.rules;
      warnings.push(...r.diagnostics.map((d) => `_redirects: ${d.message}`));
    }
    if (hdr && hdr.size <= META_FILES) {
      const r = parseHeadersFile((await this.cas.read(hdr.sha256)).toString('utf8'));
      headers = r.blocks;
      warnings.push(...r.diagnostics.map((d) => `_headers: ${d.message}`));
    }
    return { redirects, headers, warnings };
  }

  async rollback(cred, space, number) {
    const target = this.version(space.id, Number(number));
    if (!target) throw httpErr(404, 'No such version');
    const entries = new Map(this.manifest(target.id).map((f) => [f.path, f]));
    return this.createVersion(cred, space, entries, { message: `Rollback to v${target.number}`, source: 'ui' });
  }

  // ---- diff (computed from manifests on demand) ----
  diff(space, a, b) {
    const va = this.version(space.id, Number(a)), vb = this.version(space.id, Number(b));
    if (!va || !vb) throw httpErr(404, 'No such version');
    const ma = new Map(this.manifest(va.id).map((f) => [f.path, f]));
    const mb = new Map(this.manifest(vb.id).map((f) => [f.path, f]));
    const out = { from: va.number, to: vb.number, added: [], removed: [], changed: [] };
    for (const [p, f] of mb) {
      if (!ma.has(p)) out.added.push({ path: p, size: f.size });
      else if (ma.get(p).sha256 !== f.sha256) out.changed.push({ path: p, from: ma.get(p).size, to: f.size });
    }
    for (const [p, f] of ma) if (!mb.has(p)) out.removed.push({ path: p, size: f.size });
    return out;
  }

  /** Line diff for small text files. */
  async textDiff(space, a, b, path) {
    const fa = this.file(this.version(space.id, Number(a))?.id, path), fb = this.file(this.version(space.id, Number(b))?.id, path);
    const LIMIT = 64 * 1024;
    const get = async (f) => (f && f.size <= LIMIT && /^text\/|json|xml|javascript|svg/.test(f.content_type) ? (await this.cas.read(f.sha256)).toString('utf8').split('\n') : f ? null : []);
    const [x, y] = [await get(fa), await get(fb)];
    if (x === null || y === null || x.length > 2000 || y.length > 2000) return null;
    const dp = Array.from({ length: x.length + 1 }, () => new Uint16Array(y.length + 1));
    for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const ops = [];
    let i = 0, j = 0;
    while (i < x.length && j < y.length) {
      if (x[i] === y[j]) { ops.push([' ', x[i]]); i++; j++; }
      else if (dp[i + 1][j] >= dp[i][j + 1]) ops.push(['-', x[i++]]);
      else ops.push(['+', y[j++]]);
    }
    while (i < x.length) ops.push(['-', x[i++]]);
    while (j < y.length) ops.push(['+', y[j++]]);
    return ops;
  }

  // ---- lazy GC: no timers. Runs after publish/delete or from the dashboard button, at most every N hours. ----
  maybeGc(force = false) {
    const last = this.db.prepare("SELECT value FROM meta WHERE key = 'last_gc'").get();
    if (!force && last && Date.now() - Number(last.value) < this.config.gcIntervalHours * 3600e3) return null;
    this.db.prepare("INSERT OR REPLACE INTO meta (key,value) VALUES ('last_gc', ?)").run(String(Date.now()));
    const t = now();
    this.db.prepare('DELETE FROM sessions WHERE expires_at < ? OR revoked_at IS NOT NULL').run(t);
    this.db.prepare('DELETE FROM invites WHERE expires_at < ?').run(t);
    const active = new Set(this.db.prepare('SELECT DISTINCT sha256 FROM manifest_files').all().map((r) => r.sha256));
    // Fire and forget: the result only matters to the dashboard button, which awaits `gcPromise`.
    const used = this.db.prepare('SELECT 1 FROM manifest_files WHERE sha256 = ? LIMIT 1');
    this.gcPromise = this.cas.gc(active, undefined, (sha) => !!used.get(sha)).catch(() => ({ removed: 0, freed: 0 }));
    return this.gcPromise;
  }

  stats() {
    const q = (s) => this.db.prepare(s).get();
    return {
      spaces: q('SELECT COUNT(*) c FROM spaces WHERE archived_at IS NULL').c,
      versions: q('SELECT COUNT(*) c FROM versions').c,
      users: q('SELECT COUNT(*) c FROM users').c,
      bytesReferenced: q('SELECT COALESCE(SUM(size),0) c FROM (SELECT DISTINCT sha256, size FROM manifest_files)').c,
    };
  }
}

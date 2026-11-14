// Portable export/import bundles (issue #214 section 8; format written up in docs/bundle-spec.md).
// Everything streams: exports go entry by entry from CAS into a zip on disk, imports go from a zip on
// disk entry by entry into CAS. Only the small JSON documents (space.json, versions.json, activity.json)
// are held in memory, and each is capped at maxJsonBytes.
import fs from 'node:fs';
import { httpErr } from './auth.js';
import { tx } from './db.js';
import { withZip, ZipWriter } from './zip.js';
import { cleanPath, contentType, hmac, newId, now, safeEqual, SLUG_RE } from './util.js';

export const FORMAT = 'freespace-bundle/1';
export const GENERATOR = { name: 'freespace', version: '0.4.0' };
const PRIVACY = ['team', 'link', 'public'];
const MAX_BUNDLE_ENTRIES = 100_000;
const MAX_BUNDLE_CD = 64 * 1024 * 1024;

// ---------------------------------------------------------------- export

const iso = (s) => new Date(s).toISOString();
/** Quote a path for `git fast-import` when it holds anything git would misread. */
function gitPath(p) {
  if (!/^[ "]|[\x00-\x1f"\\]/.test(p)) return p;
  return '"' + p.replace(/[\x00-\x1f"\\]/g, (c) => ({ '\n': '\\n', '\t': '\\t', '\r': '\\r', '"': '\\"', '\\': '\\\\' })[c] || '\\' + c.charCodeAt(0).toString(8).padStart(3, '0')) + '"';
}
const gitSafe = (p) => !p.split('/').some((x) => x.toLowerCase() === '.git');
const person = (name, id, ts) => {
  const n = String(name || '').replace(/[<>\n\r]/g, '').trim() || 'Unknown';
  const e = String(id || '').replace(/[^\w.-]/g, '') || 'unknown';
  return `${n} <${e}@freespace.invalid> ${ts} +0000`;
};

async function* chunks(store, sha, size) {
  let n = 0;
  for await (const c of store.cas.stream(sha)) { n += c.length; yield c; }
  if (n !== size) throw new Error(`blob ${sha} changed size while exporting`);
}

/** The `git fast-import` stream: one commit per version, in version order, files as deltas from the parent. */
async function* fastImport(store, space) {
  const marks = new Map();
  let mark = 0, last = null, prev = null;
  const st = store.db.prepare('SELECT * FROM versions WHERE space_id = ? ORDER BY number'); // kept referenced: a temporary is finalized across yields
  for (const v of st.iterate(space.id)) {
    const cur = new Map(store.manifest(v.id).filter((f) => gitSafe(f.path)).map((f) => [f.path, f]));
    // One linear branch: each commit follows the previous version, whatever its real parent was (a publish with
    // base:N branches), so every version stays reachable. The real parent goes in a trailer.
    const before = prev || new Map();
    const ops = [];
    const from = last;
    for (const p of before.keys()) if (!cur.has(p)) ops.push(`D ${gitPath(p)}\n`);
    for (const [p, f] of cur) {
      if (before.get(p)?.sha256 === f.sha256) continue;
      if (!marks.has(f.sha256)) {
        const size = store.cas.size(f.sha256);
        if (size === null) throw new Error(`missing blob ${f.sha256} for ${p}`);
        marks.set(f.sha256, ++mark);
        yield `blob\nmark :${mark}\ndata ${size}\n`;
        yield* chunks(store, f.sha256, size);
        yield '\n';
      }
      ops.push(`M 100644 :${marks.get(f.sha256)} ${gitPath(p)}\n`);
    }
    const ts = Math.floor(Date.parse(v.created_at) / 1000);
    const msg = Buffer.from(`${v.message || `Version ${v.number}`}\n\nFreespace-Version: ${v.id} (v${v.number})\nFreespace-Source: ${v.source || 'unknown'}\n${v.parent_version_id ? `Freespace-Parent: ${v.parent_version_id}\n` : ''}`);
    ++mark;
    last = mark;
    prev = cur;
    yield `commit refs/heads/main\nmark :${mark}\nauthor ${person(v.author_name, v.author_credential_id, ts)}\ncommitter ${person(v.author_name, v.author_credential_id, ts)}\ndata ${msg.length}\n`;
    yield msg;
    yield `\n${from ? `from :${from}\n` : ''}${ops.join('')}\n`;
  }
}

async function* versionsJson(store, space) {
  yield '[';
  let first = true;
  const st = store.db.prepare('SELECT * FROM versions WHERE space_id = ? ORDER BY number'); // kept referenced: a temporary is finalized across yields
  for (const v of st.iterate(space.id)) {
    yield (first ? '\n' : ',\n') + JSON.stringify({
      id: v.id, number: v.number, parent: v.parent_version_id, author: v.author_name, author_id: v.author_credential_id,
      source: v.source, message: v.message, created_at: v.created_at,
      files: store.manifest(v.id).map((f) => ({ path: f.path, sha256: f.sha256, size: f.size, type: f.content_type })),
    });
    first = false;
  }
  yield '\n]\n';
}

async function* activityJson(store, space) {
  yield '[';
  let first = true;
  // Only these columns: who/what/when. No credentials, no raw request data.
  const st = store.db.prepare('SELECT * FROM activity_log WHERE space_id = ? ORDER BY id');
  for (const a of st.iterate(space.id)) {
    let detail = {};
    try { detail = JSON.parse(a.detail_json || '{}'); } catch { /* keep {} */ }
    yield (first ? '\n' : ',\n') + JSON.stringify({
      actor_kind: a.actor_kind, actor_id: a.actor_id, action: a.action, resource_type: a.resource_type, resource_id: a.resource_id, detail, created_at: a.created_at,
    });
    first = false;
  }
  yield '\n]\n';
}

/** Writes `{slug}.freespace.zip` (or the history variant) to `outFile`. */
export async function exportBundle(store, space, { history = false, outFile, exportedAt = now() }) {
  const { cas, db } = store;
  const live = space.live_version_id ? db.prepare('SELECT * FROM versions WHERE id = ?').get(space.live_version_id) : null;
  const liveFiles = live ? store.manifest(live.id) : [];
  const zip = new ZipWriter(outFile);
  try {
    const doc = {
      format: FORMAT, kind: history ? 'history' : 'current', exported_at: exportedAt, generator: GENERATOR,
      space: {
        id: space.id, slug: space.slug, name: space.name, privacy: space.privacy, noindex: !!space.noindex,
        owner_id: space.owner_id, created_at: space.created_at, updated_at: space.updated_at,
        live_version_id: space.live_version_id, plugins: JSON.parse(space.plugins_json || '[]'),
      },
      live_version: live && { id: live.id, number: live.number, author: live.author_name, source: live.source, message: live.message, created_at: live.created_at },
    };
    await zip.add('space.json', JSON.stringify(doc, null, 2) + '\n');
    for (const f of liveFiles) {
      if (cas.size(f.sha256) === null) throw new Error(`missing blob ${f.sha256} for ${f.path}`);
      await zip.add(`site/${f.path}`, cas.stream(f.sha256));
    }
    if (history) {
      await zip.add('history/versions.json', versionsJson(store, space));
      for (const b of db.prepare('SELECT DISTINCT sha256 FROM manifest_files WHERE space_id = ? ORDER BY sha256').all(space.id)) {
        if (cas.size(b.sha256) === null) throw new Error(`missing blob ${b.sha256}`);
        await zip.add(`history/blobs/${b.sha256.slice(0, 2)}/${b.sha256}`, cas.stream(b.sha256));
      }
      await zip.add('history/history.fi', fastImport(store, space));
      await zip.add('activity.json', activityJson(store, space));
    }
    await zip.finish();
  } catch (e) {
    zip.abort();
    fs.rmSync(outFile, { force: true });
    throw e;
  }
}

// Short-lived signed download URLs (MCP export_space). Stateless: nothing to expire or clean up.
const sigOf = (secret, slug, kind, exp) => hmac(secret, `export|${slug}|${kind}|${exp}`);
export function signExport(secret, slug, history, ttlSec = 600) {
  const kind = history ? 'history' : 'current', exp = Math.floor(Date.now() / 1000) + ttlSec;
  return { path: `/export/${slug}/${kind}?exp=${exp}&sig=${sigOf(secret, slug, kind, exp)}`, expires_at: new Date(exp * 1000).toISOString() };
}
export function verifyExport(secret, slug, kind, exp, sig) {
  return /^\d+$/.test(String(exp)) && Number(exp) > Date.now() / 1000 && ['current', 'history'].includes(kind) && safeEqual(sig ?? '', sigOf(secret, slug, kind, exp));
}

// ---------------------------------------------------------------- import (untrusted input)

const ISO_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?Z$/;
const TYPE_RE = /^[\w.+-]+\/[\w.+-]+(; charset=[\w-]+)?$/;
const SHA_RE = /^[a-f0-9]{64}$/;
const bad = (m) => httpErr(400, `Invalid bundle: ${m}`);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const str = (v, what, max, { nullable = false, min = 0 } = {}) => {
  if (v == null && nullable) return null;
  if (typeof v !== 'string' || v.length < min || v.length > max) throw bad(`${what} must be a string of at most ${max} characters`);
  return v;
};
const stamp = (v, what) => {
  if (typeof v !== 'string' || !ISO_RE.test(v) || isNaN(Date.parse(v))) throw bad(`${what} must be an ISO-8601 UTC timestamp`);
  return v;
};
const id = (v, prefix, what) => {
  if (typeof v !== 'string' || !new RegExp(`^${prefix}_[A-Za-z0-9_-]{1,64}$`).test(v)) throw bad(`${what} must look like ${prefix}_…`);
  return v;
};

async function readJson(open, r, name, cap) {
  if (r.usize > cap) throw httpErr(413, `${name} is too large`);
  const parts = [];
  let n = 0;
  for await (const c of await open(r)) {
    n += c.length;
    if (n > cap) throw httpErr(413, `${name} is too large`);
    parts.push(c);
  }
  try { return JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { throw bad(`${name} is not valid JSON`); }
}

/**
 * Imports a bundle zip (already on disk). Never touches an existing space unless `replace` is set,
 * and then only its versions. IDs are kept unless they collide, then remapped.
 * Returns { space, versions, warnings, remapped }.
 */
export async function importBundle(store, cred, file, { slug: wantSlug, replace = false } = {}) {
  const { cas, db, config } = store;
  const warnings = [];
  return withZip(file, { maxEntries: MAX_BUNDLE_ENTRIES, maxCd: MAX_BUNDLE_CD }, async ({ raw, open }) => {
    const byName = new Map();
    for (const r of raw) {
      if (cleanPath(r.name) !== r.name) throw httpErr(400, `Unsafe path in archive: ${r.name}`);
      if (byName.has(r.name)) throw httpErr(400, `Duplicate path in archive: ${r.name}`);
      byName.set(r.name, r);
    }
    const spaceEntry = byName.get('space.json');
    if (!spaceEntry) throw bad('space.json is missing');
    const doc = await readJson(open, spaceEntry, 'space.json', config.maxJsonBytes);
    if (!isObj(doc) || typeof doc.format !== 'string') throw bad('space.json has no format');
    if (doc.format !== FORMAT) throw bad(`unsupported format ${JSON.stringify(String(doc.format).slice(0, 40))} (this build reads ${FORMAT})`);
    if (!isObj(doc.space)) throw bad('space.json has no space');
    const sp = doc.space;
    const hasHistory = byName.has('history/versions.json');
    if (doc.kind === 'history' && !hasHistory) throw bad('history bundle without history/versions.json');
    if (doc.kind !== 'history' && doc.kind !== 'current') throw bad('kind must be current or history');
    if (doc.kind === 'current' && hasHistory) throw bad('current bundle must not carry history/versions.json');

    const name = str(sp.name, 'space.name', 200, { min: 1 }).trim();
    if (!name) throw bad('space.name is empty');
    const slug = wantSlug ?? str(sp.slug, 'space.slug', 62);
    if (!SLUG_RE.test(slug)) throw httpErr(400, 'slug must be lowercase letters, digits and dashes');
    const privacy = sp.privacy === undefined ? 'team' : sp.privacy;
    if (!PRIVACY.includes(privacy)) throw bad('space.privacy must be team, link or public');
    const bundleSpaceId = id(sp.id, 'spc', 'space.id');
    const spaceCreated = stamp(sp.created_at, 'space.created_at');
    const spaceUpdated = sp.updated_at === undefined ? spaceCreated : stamp(sp.updated_at, 'space.updated_at');
    if (Array.isArray(sp.plugins) && sp.plugins.length) warnings.push(`Plugin data for ${sp.plugins.map((p) => String(p).slice(0, 40)).join(', ')} was not imported (plugins are not supported yet); the space is static.`);

    let budget = config.maxSpaceBytes;
    const storeEntry = async (n) => {
      const r = byName.get(n);
      let s;
      try { s = await cas.storeStream(await open(r), Math.min(r.usize, budget)); }
      catch (e) { throw httpErr(413, `Could not store ${n}: ${e.message}`); }
      budget -= s.size;
      if (s.size !== r.usize) throw bad(`${n} is not the size its zip entry declares`);
      return s;
    };
    const declaredTotal = (names) => {
      let t = 0;
      for (const n of names) {
        const r = byName.get(n);
        if (r.usize > config.maxFileBytes) throw httpErr(413, `File too large: ${n}`);
        t += r.usize;
      }
      if (t > config.maxSpaceBytes) throw httpErr(413, 'Bundle is larger than the space size limit');
    };

    // ---- the manifests: history/versions.json, or the single live version of a current bundle ----
    let versions, need = new Map(); // need: sha -> history/blobs entry name
    if (hasHistory) {
      const arr = await readJson(open, byName.get('history/versions.json'), 'history/versions.json', config.maxJsonBytes);
      if (!Array.isArray(arr) || !arr.length) throw bad('history/versions.json must be a non-empty array');
      versions = arr.map((v) => cleanVersion(v, config));
      for (const v of versions) for (const f of v.files) {
        const n = `history/blobs/${f.sha256.slice(0, 2)}/${f.sha256}`;
        if (!byName.has(n)) throw bad(`blob ${f.sha256} (${f.path}) is not in the bundle`);
        need.set(f.sha256, n);
      }
      declaredTotal(need.values());
      for (const [sha, n] of need) {
        const s = await storeEntry(n);
        if (s.sha256 !== sha) throw bad(`${n} does not match its hash`);
        for (const v of versions) for (const f of v.files) if (f.sha256 === sha && f.size !== s.size) throw bad(`${f.path} in v${v.number} declares the wrong size`);
      }
    } else {
      const site = [...byName.keys()].filter((n) => n.startsWith('site/'));
      if (!site.length) throw bad('the bundle has no site/ files');
      declaredTotal(site);
      const files = [], entries = new Map();
      for (const n of site) {
        const s = await storeEntry(n), path = n.slice(5), type = contentType(path);
        files.push({ path, sha256: s.sha256, size: s.size, type });
        entries.set(path, { path, sha256: s.sha256, size: s.size, content_type: type });
        need.set(s.sha256, n);
      }
      const lv = isObj(doc.live_version) ? doc.live_version : {};
      let vid;
      try { vid = id(lv.id, 'ver', 'live_version.id'); } catch { vid = newId('ver'); }
      versions = [{
        id: vid, number: 1, parent: null, files, entries,
        author: str(lv.author, 'live_version.author', 200, { nullable: true }) ?? 'Unknown', author_id: null,
        source: typeof lv.source === 'string' && /^[\w-]{1,32}$/.test(lv.source) ? lv.source : 'api',
        message: str(lv.message, 'live_version.message', 500, { nullable: true }),
        created_at: lv.created_at === undefined ? spaceUpdated : stamp(lv.created_at, 'live_version.created_at'),
      }];
    }
    versions.sort((a, b) => a.number - b.number);
    const byId = new Map(), numbers = new Set();
    for (const v of versions) {
      if (byId.has(v.id)) throw bad(`duplicate version id ${v.id}`);
      if (numbers.has(v.number)) throw bad(`duplicate version number ${v.number}`);
      byId.set(v.id, v);
      numbers.add(v.number);
    }
    for (const v of versions) {
      if (v.parent !== null && !(byId.has(v.parent) && byId.get(v.parent).number < v.number)) throw bad(`version ${v.number} has an unknown or later parent`);
    }
    const liveId = hasHistory ? (sp.live_version_id ?? null) : versions[0].id;
    if (liveId !== null && !byId.has(liveId)) throw bad('live_version_id is not in the history');
    if (hasHistory && liveId === null) warnings.push('The bundle has history but no live version.');

    const used = new Set(need.values());
    const orphan = raw.filter((r) => r.name.startsWith('history/blobs/') && !used.has(r.name)).length;
    if (orphan) warnings.push(`${orphan} blob(s) in the bundle are not used by any version and were skipped.`);
    const skipped = raw.filter((r) => r.name.startsWith('plugins/') || r.name.startsWith('history/plugins/')).length;
    if (skipped) warnings.push(`${skipped} plugin file(s) were skipped.`);

    // ---- activity (history bundles only; a replace keeps the existing audit trail) ----
    let activity = [];
    if (hasHistory && byName.has('activity.json')) {
      const arr = await readJson(open, byName.get('activity.json'), 'activity.json', config.maxJsonBytes);
      if (!Array.isArray(arr)) throw bad('activity.json must be an array');
      activity = arr.map(cleanActivity);
    }

    // ---- routing is compiled again here (never trusted from the bundle) ----
    const memo = new Map();
    for (const v of versions) {
      const key = `${v.entries.get('_redirects')?.sha256}|${v.entries.get('_headers')?.sha256}`;
      if (!memo.has(key)) memo.set(key, await store.compileRouting(v.entries));
      v.routing = memo.get(key);
    }

    // ---- write, all or nothing. Everything above awaited, so re-check the world inside the transaction. ----
    const result = tx(db, () => {
      const existing = db.prepare('SELECT * FROM spaces WHERE slug = ?').get(slug);
      if (existing && !replace) throw httpErr(409, `The slug "${slug}" is taken. Choose another, or ask to replace it.`);
      let spaceId, replaced = false;
      if (existing) {
        if (!cred || cred.type !== 'session') throw httpErr(403, 'Replacing a space needs a signed-in person');
        spaceId = existing.id;
        replaced = true;
        db.prepare('DELETE FROM versions WHERE space_id = ?').run(spaceId); // manifest rows cascade
      } else {
        spaceId = db.prepare('SELECT 1 FROM spaces WHERE id = ?').get(bundleSpaceId) ? newId('spc') : bundleSpaceId;
        if (spaceId !== bundleSpaceId) warnings.push(`Space id ${bundleSpaceId} already exists here; the import was given ${spaceId}.`);
      }
      const map = new Map();
      const taken = db.prepare('SELECT 1 FROM versions WHERE id = ?');
      for (const v of versions) {
        const nid = taken.get(v.id) ? newId('ver') : v.id;
        if (nid !== v.id) warnings.push(`Version id ${v.id} already exists here; it was given ${nid}.`);
        map.set(v.id, nid);
      }
      const t = now();
      const newLive = liveId && map.get(liveId);
      if (replaced) db.prepare('UPDATE spaces SET live_version_id = ?, updated_at = ? WHERE id = ?').run(newLive, t, spaceId);
      else {
        db.prepare('INSERT INTO spaces (id,slug,name,owner_id,live_version_id,created_at,updated_at,noindex,privacy,plugins_json) VALUES (?,?,?,?,?,?,?,?,?,?)')
          .run(spaceId, slug, name, cred.userId, newLive, spaceCreated, spaceUpdated, sp.noindex === false ? 0 : 1, privacy, '[]');
      }
      const insV = db.prepare(`INSERT INTO versions (id,space_id,number,status,routing_json,total_files,total_bytes,created_at,finalized_at,
        parent_version_id,author_credential_id,author_name,message,source,warnings_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
      const insF = db.prepare('INSERT INTO manifest_files (version_id,space_id,path,sha256,size,declared_size,content_type) VALUES (?,?,?,?,?,?,?)');
      for (const v of versions) {
        const total = v.files.reduce((n, f) => n + f.size, 0);
        insV.run(map.get(v.id), spaceId, v.number, 'ready', JSON.stringify({ redirects: v.routing.redirects, headers: v.routing.headers }), v.files.length, total,
          v.created_at, v.created_at, v.parent && map.get(v.parent), v.author_id, v.author, v.message, v.source, JSON.stringify(v.routing.warnings));
        for (const f of v.files) insF.run(map.get(v.id), spaceId, f.path, f.sha256, f.size, f.size, f.type);
      }
      if (!replaced) {
        const insA = db.prepare('INSERT INTO activity_log (space_id,actor_kind,actor_id,action,resource_type,resource_id,detail_json,created_at) VALUES (?,?,?,?,?,?,?,?)');
        for (const a of activity) insA.run(spaceId, a.actor_kind, a.actor_id, a.action, a.resource_type, a.resource_id, a.detail, a.created_at);
      } else if (hasHistory) warnings.push("The bundle's activity log was not imported; the space keeps its own.");
      return { spaceId, replaced, remapped: warnings.some((w) => /already exists here/.test(w)) };
    });
    store.log(cred, 'space.imported', result.spaceId, { kind: doc.kind, versions: versions.length, replaced: result.replaced, from: bundleSpaceId, generator: isObj(doc.generator) ? String(doc.generator.name).slice(0, 40) : null }, { type: 'space', id: result.spaceId });
    store.maybeGc();
    return { space: store.spaceById(result.spaceId), versions: versions.length, warnings, remapped: result.remapped };
  });
}

function cleanFiles(list, what, config) {
  if (!Array.isArray(list) || !list.length) throw bad(`${what}.files must be a non-empty array`);
  const seen = new Set(), entries = new Map(), files = [];
  let total = 0;
  for (const f of list) {
    if (!isObj(f)) throw bad(`${what}: a file entry is not an object`);
    const p = typeof f.path === 'string' ? cleanPath(f.path) : null;
    if (!p || p !== f.path) throw bad(`${what}: unsafe or non-canonical path ${JSON.stringify(String(f.path).slice(0, 100))}`);
    if (seen.has(p)) throw bad(`${what}: duplicate path ${p}`);
    seen.add(p);
    if (typeof f.sha256 !== 'string' || !SHA_RE.test(f.sha256)) throw bad(`${what}: ${p} has no valid sha256`);
    if (!Number.isSafeInteger(f.size) || f.size < 0 || f.size > config.maxFileBytes) throw bad(`${what}: ${p} has an invalid size`);
    total += f.size;
    // A declared type is kept only if it looks like a MIME type; otherwise it is derived from the path.
    const type = typeof f.type === 'string' && f.type.length <= 100 && TYPE_RE.test(f.type) ? f.type : contentType(p);
    const e = { path: p, sha256: f.sha256, size: f.size, type };
    files.push(e);
    entries.set(p, { ...e, content_type: type });
  }
  if (total > config.maxSpaceBytes) throw httpErr(413, `${what} is larger than the space size limit`);
  return { files, entries };
}

function cleanVersion(v, config) {
  if (!isObj(v)) throw bad('a version is not an object');
  const vid = id(v.id, 'ver', 'version id');
  const what = `version ${vid}`;
  if (!Number.isSafeInteger(v.number) || v.number < 1) throw bad(`${what}: number must be a positive integer`);
  const parent = v.parent == null ? null : id(v.parent, 'ver', `${what} parent`);
  return {
    id: vid, number: v.number, parent, ...cleanFiles(v.files, what, config),
    author: str(v.author, `${what} author`, 200, { nullable: true }) ?? 'Unknown',
    author_id: str(v.author_id, `${what} author_id`, 100, { nullable: true }),
    source: v.source == null ? 'api' : (typeof v.source === 'string' && /^[\w-]{1,32}$/.test(v.source) ? v.source : (() => { throw bad(`${what}: bad source`); })()),
    message: str(v.message, `${what} message`, 500, { nullable: true }),
    created_at: stamp(v.created_at, `${what} created_at`),
  };
}

function cleanActivity(a) {
  if (!isObj(a)) throw bad('an activity entry is not an object');
  const detail = JSON.stringify(isObj(a.detail) ? a.detail : {});
  return {
    actor_kind: str(a.actor_kind, 'activity actor_kind', 32, { min: 1 }),
    actor_id: str(a.actor_id, 'activity actor_id', 100, { nullable: true }),
    action: str(a.action, 'activity action', 100, { min: 1 }),
    resource_type: str(a.resource_type, 'activity resource_type', 100, { nullable: true }),
    resource_id: str(a.resource_id, 'activity resource_id', 100, { nullable: true }),
    detail: detail.length <= 8192 ? detail : '{"truncated":true}',
    created_at: stamp(a.created_at, 'activity created_at'),
  };
}

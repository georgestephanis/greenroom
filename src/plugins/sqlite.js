// The sqlite plugin: one SQLite database per space (node:sqlite, no native deps) for the space's own
// pages, plus MCP tools and per-space snapshots tied to versions.
//   browser -> structured ops only (select/insert/update/delete + filters), gated by a per-table policy
//              and a per-document token (rule 7). The browser never sends SQL.
//   MCP     -> raw SQL, needs the `db` scope.
// The connection is opened per call and closed after it: no timers, nothing idle to hold memory.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { DatabaseSync } from 'node:sqlite';
import { definePlugin } from '../plugins.js';
import { httpErr } from '../auth.js';
import { injectDocToken } from '../security.js';
import { sha256hex, now } from '../util.js';

const MAX_PAGES = 25600; // ~100 MB at 4 KiB pages: a runaway insert can't fill a small box
const MAX_BYTES = 100 * 1024 * 1024; // database size cap; max_page_count is derived from the file's page size
const MAX_SNAPSHOTS = 100; // the most `keep` allows
const MAX_ROWS = 1000;
const POLICY = ['off', 'read', 'read+insert', 'read+write'];
const RANK = Object.fromEntries(POLICY.map((p, i) => [p, i]));
const OPS = { '=': '=', '!=': '!=', '<': '<', '<=': '<=', '>': '>', '>=': '>=', like: 'LIKE' };
const MAGIC = 'SQLite format 3\0';

const dbFile = (dir) => path.join(dir, 'app.sqlite');
const quote = (id) => `"${id.replace(/"/g, '""')}"`;
const lit = (s) => `'${s.replace(/'/g, "''")}'`;
const plain = (row) => ({ ...row }); // node:sqlite rows have a null prototype

function open(dir, { readOnly = false, create = false } = {}) {
  if (!create && !fs.existsSync(dbFile(dir))) return null;
  const db = new DatabaseSync(dbFile(dir), { readOnly });
  if (!readOnly) db.exec(`PRAGMA max_page_count = ${MAX_PAGES}; PRAGMA foreign_keys = ON`);
  return db;
}
function withDb(dir, opts, fn) {
  const db = open(dir, opts);
  if (!db) return fn(null);
  try { return fn(db); } finally { db.close(); }
}

const tables = (db) => db.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name").all().map((r) => r.name);
const columns = (db, t) => db.prepare(`PRAGMA table_info(${quote(t)})`).all().map((c) => ({ name: c.name, type: c.type, pk: !!c.pk, notnull: !!c.notnull }));
const schemaHash = (db) => sha256hex(db.prepare('SELECT type, name, sql FROM sqlite_schema ORDER BY type, name').all().map((r) => `${r.type}|${r.name}|${r.sql}`).join('\n'));

// Raw SQL from MCP. Only the first statement of a string runs (that is how node:sqlite prepares), so the
// guard looks at the first keyword: no ATTACH (it would reach other files, including the core database),
// no VACUUM INTO (writes arbitrary paths), no PRAGMA. Several statements go in as an array.
function guard(sql, allowed) {
  if (typeof sql !== 'string' || !sql.trim()) throw httpErr(400, 'sql must be a non-empty string');
  const first = sql.replace(/^(\s|--[^\n]*\n|\/\*[\s\S]*?\*\/)+/, '').match(/^[a-z]+/i)?.[0].toUpperCase();
  if (!allowed.includes(first)) throw httpErr(400, `Only ${allowed.join(', ')} statements are allowed here`);
  // ponytail: prepare() would silently run only the first statement; refuse a second one instead (use the array form, and ? params for text holding ';').
  if (/;\s*[^\s;]/.test(sql)) throw httpErr(400, 'One statement per string; pass an array to run several');
  return sql;
}
const params = (a) => {
  const p = a ?? [];
  if (!Array.isArray(p) || p.some((v) => v !== null && !['string', 'number', 'boolean'].includes(typeof v))) throw httpErr(400, 'params must be an array of strings, numbers, booleans or null');
  return p.map((v) => (typeof v === 'boolean' ? Number(v) : v));
};
const wrap = (fn) => { try { return fn(); } catch (e) { throw e.status ? e : httpErr(400, `SQL error: ${e.message}`); } };

// ---- structured ops (the browser) ----
function filters(db, cols, where) {
  if (where === undefined) return { sql: '', args: [] };
  if (!Array.isArray(where) || where.length > 20) throw httpErr(400, 'where must be an array of up to 20 filters');
  const parts = [], args = [];
  for (const f of where) {
    if (!f || !cols.includes(f.col) || !OPS[f.op] || !['string', 'number', 'boolean'].includes(typeof f.value)) throw httpErr(400, 'Each filter needs a known column, an operator (= != < <= > >= like) and a value');
    parts.push(`${quote(f.col)} ${OPS[f.op]} ?`);
    args.push(typeof f.value === 'boolean' ? Number(f.value) : f.value);
  }
  return { sql: parts.length ? ` WHERE ${parts.join(' AND ')}` : '', args };
}
function values(cols, v) {
  const keys = v && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v) : [];
  if (!keys.length || keys.some((k) => !cols.includes(k))) throw httpErr(400, 'values must be an object of known columns');
  return { keys, args: params(keys.map((k) => v[k])) };
}
function structured(dir, policy, b) {
  if (!b || typeof b !== 'object') throw httpErr(400, 'Bad request');
  return withDb(dir, { readOnly: b.op === 'select' || b.op === 'tables' }, (db) => {
    if (!db) { if (b.op === 'tables') return { tables: [] }; throw httpErr(404, 'This space has no database yet'); }
    const visible = tables(db).filter((t) => (RANK[policy[t]] ?? 0) > 0);
    if (b.op === 'tables') return { tables: visible.map((t) => ({ name: t, access: policy[t], columns: columns(db, t) })) };
    const need = { select: 1, insert: 2, update: 3, delete: 3 }[b.op];
    if (!need) throw httpErr(400, 'op must be select, insert, update, delete or tables');
    if (!visible.includes(b.table)) throw httpErr(404, 'No such table');
    if ((RANK[policy[b.table]] ?? 0) < need) throw httpErr(403, `This table is ${policy[b.table]}; ${b.op} is not allowed`);
    const cols = columns(db, b.table).map((c) => c.name), t = quote(b.table);
    return wrap(() => {
      if (b.op === 'select') {
        const w = filters(db, cols, b.where);
        const order = (b.order ?? []).map((o) => {
          if (!cols.includes(o?.col)) throw httpErr(400, 'Unknown order column');
          return `${quote(o.col)} ${o.dir === 'desc' ? 'DESC' : 'ASC'}`;
        });
        const limit = Math.min(Math.max(Math.trunc(Number(b.limit ?? 100)) || 0, 1), MAX_ROWS);
        const offset = Math.max(Math.trunc(Number(b.offset ?? 0)) || 0, 0);
        return { rows: db.prepare(`SELECT * FROM ${t}${w.sql}${order.length ? ` ORDER BY ${order.join(', ')}` : ''} LIMIT ${limit} OFFSET ${offset}`).all(...w.args).map(plain) };
      }
      let r;
      if (b.op === 'insert') {
        const v = values(cols, b.values);
        r = db.prepare(`INSERT INTO ${t} (${v.keys.map(quote).join(', ')}) VALUES (${v.keys.map(() => '?').join(', ')})`).run(...v.args);
      } else {
        const w = filters(db, cols, b.where);
        if (!w.args.length) throw httpErr(400, `${b.op} needs at least one filter`);
        if (b.op === 'update') {
          const v = values(cols, b.values);
          r = db.prepare(`UPDATE ${t} SET ${v.keys.map((k) => `${quote(k)} = ?`).join(', ')}${w.sql}`).run(...v.args, ...w.args);
        } else r = db.prepare(`DELETE FROM ${t}${w.sql}`).run(...w.args);
      }
      return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) };
    });
  });
}

// ---- snapshots ----
const stateFile = (dir) => path.join(dir, 'snapshots.json');
const readState = (dir) => { try { return JSON.parse(fs.readFileSync(stateFile(dir), 'utf8')); } catch { return { schema: null, snapshots: [] }; } };
const writeState = (dir, s) => fs.writeFileSync(stateFile(dir), JSON.stringify(s, null, 2));

/** VACUUM INTO a temp file (a consistent copy, even mid-write), keep it in the CAS. Identical copies dedupe there. */
function copyOut(dir, tmpDir) {
  const tmp = path.join(tmpDir, `sqlite-${crypto.randomUUID()}`);
  withDb(dir, { readOnly: true }, (db) => db.exec(`VACUUM INTO ${lit(tmp)}`));
  return tmp;
}
async function snapshot(ctx, space, dir, version, trigger, keep) {
  if (!fs.existsSync(dbFile(dir))) return null;
  const tmp = copyOut(dir, ctx.tmpDir);
  try {
    const { sha256, size } = await ctx.cas.storeStream(fs.createReadStream(tmp));
    const st = readState(dir);
    st.snapshots = [{ version, sha256, size, created_at: now(), trigger }, ...st.snapshots].slice(0, keep);
    st.schema = withDb(dir, { readOnly: true }, schemaHash);
    writeState(dir, st);
    return st.snapshots[0];
  } finally { fs.rmSync(tmp, { force: true }); }
}

export default definePlugin({
  name: 'sqlite',
  version: '1.0.0',
  description: 'A SQLite database for the space’s own pages, MCP tools and snapshots tied to versions.',
  spaceSettings: {
    tables: { type: 'map', values: POLICY, default: {}, label: 'Browser access per table (off, read, read+insert, read+write)' },
    snapshots: { type: 'enum', values: ['off', 'schema', 'publish', 'manual'], default: 'schema', label: 'Snapshots: off, on schema change, on every publish, manual' },
    keep: { type: 'number', min: 1, max: 100, default: 10, label: 'Snapshots to keep' },
  },
  register(ctx) {
    // Rule 7: documents of spaces with this plugin carry a short-lived token in a <meta>; /_fs/db needs it.
    ctx.transform(({ html, docToken }) => injectDocToken(html, docToken()));

    ctx.serve({
      path: '/_fs/db.js', auth: 'none',
      handler: () => ({ type: 'text/javascript; charset=utf-8', body: CLIENT }), // carries no secret
    });
    ctx.serve({
      path: '/_fs/db', methods: ['POST'], auth: 'token',
      handler: ({ body, settings, dir }) => ({ json: structured(dir, settings.tables, body) }),
    });

    const slugArg = { slug: { type: 'string', description: 'Space slug' } };
    ctx.mcp.tool('db_schema', { description: 'Tables and columns of the space’s SQLite database, with each table’s browser access policy.', inputSchema: { type: 'object', properties: {}, required: [] }, perm: 'db' },
      ({ dir, settings }) => withDb(dir, { readOnly: true }, (db) => ({ tables: db ? tables(db).map((t) => ({ name: t, access: settings.tables[t] ?? 'off', columns: columns(db, t) })) : [] })));
    ctx.mcp.tool('db_query', { description: `Run one read-only SQL statement (SELECT, WITH or EXPLAIN) with ? parameters. Up to ${MAX_ROWS} rows.`, inputSchema: { type: 'object', properties: { sql: { type: 'string' }, params: { type: 'array' } }, required: ['sql'] }, perm: 'db' },
      ({ args, dir }) => withDb(dir, { readOnly: true }, (db) => {
        if (!db) throw httpErr(404, 'This space has no database yet');
        guard(args.sql, ['SELECT', 'WITH', 'EXPLAIN']);
        return wrap(() => {
          const rows = [];
          for (const r of db.prepare(args.sql).iterate(...params(args.params))) { // ponytail: row cap only; a pathological query can still run long
            rows.push(plain(r));
            if (rows.length >= MAX_ROWS) break;
          }
          return { rows, truncated: rows.length >= MAX_ROWS };
        });
      }));
    ctx.mcp.tool('db_exec', { description: 'Run SQL that changes the database (INSERT, UPDATE, DELETE, REPLACE, CREATE, DROP, ALTER). One statement per string; pass an array to run several in one transaction. Creates the database on first use.', inputSchema: { type: 'object', properties: { sql: { oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }] }, params: { type: 'array' } }, required: ['sql'] }, perm: 'db' },
      ({ args, dir }) => {
        const list = [].concat(args.sql);
        if (list.length > 100) throw httpErr(400, 'At most 100 statements per call');
        for (const s of list) guard(s, ['INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'CREATE', 'DROP', 'ALTER', 'WITH']);
        fs.mkdirSync(dir, { recursive: true });
        return withDb(dir, { create: true }, (db) => wrap(() => {
          let changes = 0;
          db.exec('BEGIN');
          try {
            for (const s of list) changes += Number(db.prepare(s).run(...(list.length === 1 ? params(args.params) : [])).changes);
            db.exec('COMMIT');
          } catch (e) { db.exec('ROLLBACK'); throw e; }
          return { changes };
        }));
      });
    ctx.mcp.tool('db_checkpoint', { description: 'Snapshots of the database. action: "create" now, "list", or "restore" a version number (the current database is snapshotted first).', inputSchema: { type: 'object', properties: { action: { enum: ['create', 'list', 'restore'] }, version: { type: 'number' } }, required: ['action'] }, perm: 'db' },
      async ({ args, dir, settings, space }) => {
        const cur = ctx.currentVersion?.(space);
        if (args.action === 'list') return { snapshots: readState(dir).snapshots };
        if (args.action === 'create') return { snapshot: await snapshot(ctx, space, dir, cur ?? 0, 'manual', settings.keep) ?? null };
        if (args.action !== 'restore') throw httpErr(400, 'action must be create, list or restore');
        const snap = readState(dir).snapshots.find((s) => s.version === args.version);
        if (!snap || !ctx.cas.has(snap.sha256)) throw httpErr(404, 'No such snapshot');
        await snapshot(ctx, space, dir, cur ?? 0, 'before-restore', settings.keep);
        await restore(ctx, dir, ctx.cas.stream(snap.sha256));
        return { restored: snap.version };
      });

    // Snapshots follow versions: after a publish, per the space's mode.
    ctx.on('version.created', async ({ space, number, settings, dir }) => {
      const mode = settings.snapshots;
      if (mode === 'off' || mode === 'manual' || !fs.existsSync(dbFile(dir))) return;
      if (mode === 'schema' && readState(dir).schema === withDb(dir, { readOnly: true }, schemaHash)) return;
      await snapshot(ctx, space, dir, number, mode === 'schema' ? 'schema-change' : 'publish', settings.keep);
    });

    // The lazy GC must not reclaim snapshot blobs.
    ctx.blobs(() => ctx.allDirs().flatMap((d) => readState(d).snapshots.map((s) => s.sha256)));

    // Bundles: the live database in both zips, snapshots in the history zip.
    ctx.export(({ dir, history, add, addHistory, tmpDir }) => {
      if (fs.existsSync(dbFile(dir))) {
        const tmp = copyOut(dir, tmpDir);
        const fd = fs.openSync(tmp, 'r');
        fs.unlinkSync(tmp); // the open descriptor keeps it readable until the zip has consumed it
        add('app.sqlite', fs.createReadStream(null, { fd }));
      }
      if (history) {
        const snaps = readState(dir).snapshots.filter((s) => ctx.cas.has(s.sha256));
        addHistory('snapshots.json', JSON.stringify(snaps, null, 2));
        for (const sha of new Set(snaps.map((s) => s.sha256))) addHistory(`snapshots/${sha}.sqlite`, ctx.cas.stream(sha));
      }
    });
    ctx.import(async ({ dir, files, warn }) => {
      fs.mkdirSync(dir, { recursive: true });
      const keep = new Set();
      let records = [];
      for (const f of files) {
        if (f.rel === 'app.sqlite' && !f.history) await restore(ctx, dir, await f.open()).catch((e) => warn(`The sqlite database was not imported: ${e.message}`));
        else if (f.rel === 'snapshots.json' && f.history) {
          try { records = JSON.parse((await readBuf(await f.open(), 1 << 20)).toString('utf8')); } catch { warn('Snapshot list was not valid and was dropped.'); }
        } else if (/^snapshots\/[a-f0-9]{64}\.sqlite$/.test(f.rel) && f.history) {
          const sha = f.rel.slice(10, 74);
          if (keep.size >= MAX_SNAPSHOTS) { warn(`More than ${MAX_SNAPSHOTS} snapshots; the rest were skipped.`); continue; }
          // ponytail: a blob that fails its checksum is already in the CAS; nothing references it, so the lazy GC reclaims it (bytes still count against the import budget).
          const got = await ctx.cas.storeStream(await f.open(), MAX_BYTES).catch((e) => ({ error: e.message }));
          if (got.sha256 === sha) keep.add(sha);
          else warn(`Snapshot ${sha.slice(0, 8)} was skipped: ${got.error ?? 'checksum mismatch'}.`);
        }
      }
      const snaps = (Array.isArray(records) ? records : []).filter((s) => keep.has(s?.sha256) && Number.isInteger(s.version)).slice(0, MAX_SNAPSHOTS);
      writeState(dir, { schema: null, snapshots: snaps });
    });
  },
});

/** Replace the space's database with a stream, after checking it is a SQLite file within the size cap. */
async function restore(ctx, dir, stream) {
  fs.mkdirSync(dir, { recursive: true });
  const tmp = path.join(ctx.tmpDir, `restore-${crypto.randomUUID()}`);
  let n = 0;
  stream.on('data', (c) => { n += c.length; if (n > MAX_BYTES) stream.destroy(new Error('database is too large')); });
  try {
    await pipeline(stream, fs.createWriteStream(tmp));
    const head = Buffer.alloc(16), fd = fs.openSync(tmp, 'r');
    fs.readSync(fd, head, 0, 16, 0);
    fs.closeSync(fd);
    if (head.toString('latin1') !== MAGIC) throw new Error('not a SQLite database');
    fs.renameSync(tmp, dbFile(dir));
  } finally { fs.rmSync(tmp, { force: true }); }
}
async function readBuf(stream, cap) {
  const chunks = [];
  let n = 0;
  for await (const c of stream) { n += c.length; if (n > cap) throw new Error('too large'); chunks.push(c); }
  return Buffer.concat(chunks);
}

// What pages load as <script src="/s/{slug}/_fs/db.js">. It reads the token from the <meta> tag core
// injected into this very document; nothing secret is in this file.
const CLIENT = `(() => {
  const url = document.currentScript.src.replace(/db\\.js(\\?.*)?$/, 'db');
  const call = async (body) => {
    const token = document.querySelector('meta[name="freespace-doc-token"]')?.content;
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-fs-doc-token': token || '' }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'Request failed (' + r.status + ')');
    return j;
  };
  window.freespace = Object.assign(window.freespace || {}, { db: {
    tables: () => call({ op: 'tables' }).then((j) => j.tables),
    select: (table, o = {}) => call({ op: 'select', table, ...o }).then((j) => j.rows),
    insert: (table, values) => call({ op: 'insert', table, values }),
    update: (table, values, where) => call({ op: 'update', table, values, where }),
    delete: (table, where) => call({ op: 'delete', table, where }),
  } });
})();
`;

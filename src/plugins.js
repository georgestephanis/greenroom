// Plugin loader (issue #214 section 3). A plugin is a plain object with register(ctx); ctx is the whole
// API. It deliberately has no database handle to core tables, no way to mint or check credentials, and
// no way to touch CSP or reserved cookies: core resolves the viewer or token, then calls the handler,
// then filters whatever comes back. register() runs once at startup and must stay cheap; do heavy
// setup the first time a handler runs.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { httpErr } from './auth.js';
import { signDocToken } from './security.js';
import sqlite from './plugins/sqlite.js';
import watermark from './plugins/watermark.js';

export function definePlugin(def) { return def; } // ponytail: identity, one entry point for editors and docs; a declaration so the import cycle with the bundled plugins is safe

const NAME = /^[a-z][a-z0-9-]{0,30}$/;
const EVENTS = ['version.created', 'space.deleted'];
const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/** Check a settings patch against a plugin's `spaceSettings` spec; unknown keys are an error. */
export function cleanSettings(spec = {}, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw httpErr(400, 'settings must be an object');
  const out = {};
  for (const [k, v] of Object.entries(input)) {
    const s = spec[k];
    if (!s) throw httpErr(400, `Unknown setting: ${k}`);
    const ok = {
      bool: () => typeof v === 'boolean',
      string: () => typeof v === 'string' && v.length <= (s.max ?? 200),
      number: () => Number.isFinite(v) && v >= (s.min ?? -Infinity) && v <= (s.max ?? Infinity),
      enum: () => s.values.includes(v),
      // map: identifier -> one of `values` (the sqlite per-table policy)
      map: () => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length <= 100
        && Object.entries(v).every(([a, b]) => IDENT.test(a) && s.values.includes(b)),
    }[s.type];
    if (!ok?.()) throw httpErr(400, `Invalid value for setting "${k}"`);
    out[k] = v;
  }
  return out;
}

export function createPlugins({ store, config, installed = [] }) {
  const { db } = store;
  const defs = new Map(); // name -> { def, routes, transforms, tools, hooks, exporters, importers, blobs }
  const dirOf = (space, name) => path.join(config.dataDir, 'spaces', space.id, 'plugins', name);

  const meta = db.prepare('SELECT value FROM meta WHERE key = ?');
  const instanceNames = () => { try { return JSON.parse(meta.get('plugins.enabled')?.value ?? '[]'); } catch { return []; } };
  const listed = (space) => JSON.parse(space.plugins_json || '[]');

  function load(def) {
    if (!def || !NAME.test(def.name ?? '') || typeof def.register !== 'function') throw new Error('plugin needs a lowercase name and register(ctx)');
    if (defs.has(def.name)) throw new Error(`duplicate plugin: ${def.name}`);
    const p = { def, routes: [], transforms: [], tools: new Map(), hooks: {}, exporters: [], importers: [], blobs: [] };
    const name = def.name;
    const ctx = {
      name,
      /** Route under /s/{slug}/_fs/...; `auth` is 'token' (per-document token, rule 7) or 'none' (public, static). */
      serve({ path: route, methods = ['GET'], auth = 'token', handler }) {
        if (!/^\/_fs\/[\w.-]+$/.test(route) || !['token', 'none'].includes(auth)) throw new Error(`bad route: ${route}`);
        p.routes.push({ path: route, methods, auth, handler, plugin: name });
      },
      /** Rewrite HTML documents at serve time. Receives { space, html, viewer, settings, docToken }. */
      transform(fn) { p.transforms.push(fn); },
      mcp: { tool(tname, spec, handler) { p.tools.set(tname, { ...spec, name: tname, handler, plugin: name }); } },
      on(event, fn) { if (!EVENTS.includes(event)) throw new Error(`unknown event: ${event}`); (p.hooks[event] ??= []).push(fn); },
      export(fn) { p.exporters.push(fn); },
      import(fn) { p.importers.push(fn); },
      /** Return the CAS blobs this plugin still references; the lazy GC keeps them. */
      blobs(fn) { p.blobs.push(fn); },
      cas: { storeStream: (r, max) => store.cas.storeStream(r, max), read: (sha) => store.cas.read(sha), stream: (sha) => store.cas.stream(sha), has: (sha) => store.cas.has(sha) },
      dir(space) { const d = dirOf(space, name); fs.mkdirSync(d, { recursive: true }); return d; },
      settings: (space) => settingsOf(space, name),
      tmpDir: config.tmpDir,
      /** The number of the space's live version, or null. (A number, not a row: core tables stay out of reach.) */
      currentVersion: (space) => db.prepare('SELECT v.number FROM versions v JOIN spaces s ON s.live_version_id = v.id WHERE s.id = ?').get(space.id)?.number ?? null,
      /** This plugin's data directory in every space (for GC to find the blobs it references). */
      allDirs: () => fs.readdirSync(path.join(config.dataDir, 'spaces'), { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => path.join(config.dataDir, 'spaces', e.name, 'plugins', name)).filter((d) => fs.existsSync(d)),
    };
    defs.set(name, p);
    def.register(ctx);
  }
  for (const d of [sqlite, watermark, ...installed]) load(d);

  const row = db.prepare('SELECT settings_json FROM plugin_space WHERE space_id = ? AND plugin = ?');
  function settingsOf(space, name) {
    const spec = defs.get(name)?.def.spaceSettings ?? {};
    const out = Object.fromEntries(Object.entries(spec).map(([k, s]) => [k, s.default]));
    try { Object.assign(out, JSON.parse(row.get(space.id, name)?.settings_json ?? '{}')); } catch {}
    return out;
  }
  const rawSettings = (space, name) => { try { return JSON.parse(row.get(space.id, name)?.settings_json ?? '{}'); } catch { return {}; } };
  const saveSettings = (spaceId, name, obj) => db.prepare(
    'INSERT INTO plugin_space (space_id, plugin, settings_json) VALUES (?,?,?) ON CONFLICT(space_id, plugin) DO UPDATE SET settings_json = excluded.settings_json',
  ).run(spaceId, name, JSON.stringify(obj));

  /** Plugins that may act on this space right now: installed, enabled by an admin, and switched on for it. */
  const active = (space) => {
    const on = instanceNames();
    return listed(space).filter((n) => defs.has(n) && on.includes(n));
  };
  const get = (n) => defs.get(n);

  const api = {
    definePlugin,
    names: () => [...defs.keys()],
    installed: (n) => defs.has(n),
    instanceEnabled: (n) => instanceNames().includes(n),
    listed,
    active,
    settings: settingsOf,
    spec: (n) => defs.get(n)?.def.spaceSettings ?? {},
    info: (n) => defs.get(n) && { name: n, version: defs.get(n).def.version ?? '', description: defs.get(n).def.description ?? '' },

    setInstanceEnabled(name, on) {
      if (!defs.has(name)) throw httpErr(404, 'No such plugin');
      const set = new Set(instanceNames());
      on ? set.add(name) : set.delete(name);
      db.prepare("INSERT INTO meta (key,value) VALUES ('plugins.enabled', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(JSON.stringify([...set]));
    },
    /** Switch a plugin on or off for one space and/or change its settings. Callers check credentials first. */
    configure(space, name, { enabled, settings }) {
      const p = defs.get(name);
      if (!p) throw httpErr(404, 'No such plugin');
      const patch = settings === undefined ? undefined : cleanSettings(p.def.spaceSettings, settings);
      if (enabled === true && !instanceNames().includes(name)) throw httpErr(409, 'An admin has to enable this plugin for the instance first');
      if (enabled !== undefined) {
        const set = new Set(listed(space));
        enabled ? set.add(name) : set.delete(name);
        db.prepare('UPDATE spaces SET plugins_json = ? WHERE id = ?').run(JSON.stringify([...set]), space.id);
      }
      if (patch) saveSettings(space.id, name, { ...rawSettings(space, name), ...patch });
    },

    // ---- serving ----
    route(space, subpath) {
      for (const n of active(space)) for (const r of get(n).routes) if (r.path === subpath) return r;
      return null;
    },
    callRoute: (space, r, input) => r.handler({ ...input, space: { id: space.id, slug: space.slug }, settings: settingsOf(space, r.plugin), dir: dirOf(space, r.plugin) }),
    hasTransforms: (space) => active(space).some((n) => get(n).transforms.length),
    async transform(space, { html, viewer }) {
      for (const n of active(space)) {
        for (const fn of get(n).transforms) {
          const out = await fn({ space: { id: space.id, slug: space.slug, name: space.name }, html, viewer, settings: settingsOf(space, n), docToken: () => signDocToken(config.secret, space) });
          if (typeof out === 'string') html = out;
        }
      }
      return html;
    },

    // ---- MCP ----
    tools: () => [...defs.values()].flatMap((p) => [...p.tools.values()]),
    tool: (name) => [...defs.values()].map((p) => p.tools.get(name)).find(Boolean),
    async callTool(space, t, args) {
      return t.handler({ space: { id: space.id, slug: space.slug }, args, settings: settingsOf(space, t.plugin), dir: dirOf(space, t.plugin), ctx: { cas: store.cas } });
    },

    // ---- lifecycle ----
    async emit(event, payload) {
      for (const n of active(payload.space)) {
        for (const fn of get(n).hooks[event] ?? []) {
          try { await fn({ ...payload, settings: settingsOf(payload.space, n), dir: dirOf(payload.space, n) }); } catch (e) { console.error(`plugin ${n} ${event}:`, e.message); }
        }
      }
    },
    removeData(space) { fs.rmSync(path.join(config.dataDir, 'spaces', space.id), { recursive: true, force: true }); },
    keepBlobs() {
      const out = new Set();
      for (const p of defs.values()) for (const fn of p.blobs) { try { for (const s of fn()) out.add(s); } catch {} }
      return out;
    },

    // ---- bundles (section 8) ----
    /** Add every plugin's files for a space. `add(zipPath, content)`; `history` also asks for history data. */
    async exportInto(space, { add, history }) {
      const on = active(space);
      for (const n of listed(space)) {
        const s = rawSettings(space, n);
        if (Object.keys(s).length) await add(`plugins/${n}/settings.json`, JSON.stringify(s, null, 2));
        if (on.includes(n)) {
          const p = get(n);
          for (const fn of p.exporters) {
            // Zip entries are written one at a time, so serialise `add` even when a hook forgets to await it.
            let q = Promise.resolve();
            const seq = (name, c) => (q = q.then(() => add(name, c)));
            await fn({ space, dir: dirOf(space, n), history, settings: settingsOf(space, n), add: (rel, c) => seq(`plugins/${n}/${rel}`, c), addHistory: (rel, c) => seq(`history/plugins/${n}/${rel}`, c), tmpDir: config.tmpDir });
            await q;
          }
        } else {
          // Not installed here (or switched off): carry its files through untouched.
          const base = dirOf(space, n);
          for (const rel of await walk(base)) if (history || !rel.startsWith('history/')) await add(`${rel.startsWith('history/') ? 'history/' : ''}plugins/${n}/${rel.replace(/^history\//, '')}`, fs.createReadStream(path.join(base, rel)));
        }
      }
    },
    /** `files`: { [plugin]: [{ rel, history, open() }] } from the bundle. Warnings go in `warn`. */
    async importFrom(spaceId, names, files, warn) {
      const space = { id: spaceId };
      const on = new Set(instanceNames());
      for (const n of names) {
        const mine = files[n] ?? [];
        const set = mine.find((f) => f.rel === 'settings.json' && !f.history);
        if (set) {
          try {
            const raw = JSON.parse((await readAll(await set.open(), 64 * 1024)).toString('utf8'));
            saveSettings(spaceId, n, defs.has(n) ? cleanSettings(get(n).def.spaceSettings, raw) : raw);
          } catch { warn(`Settings for plugin "${n}" were not valid and were dropped.`); }
        }
        const rest = mine.filter((f) => f !== set);
        const p = get(n);
        if (p && on.has(n) && p.importers.length) {
          for (const fn of p.importers) await fn({ space, dir: path.join(config.dataDir, 'spaces', spaceId, 'plugins', n), files: rest, warn, tmpDir: config.tmpDir });
        } else if (rest.length) {
          const base = path.join(config.dataDir, 'spaces', spaceId, 'plugins', n);
          for (const f of rest) {
            const dest = path.join(base, f.history ? 'history' : '', f.rel);
            if (!dest.startsWith(base + path.sep)) continue;
            await fsp.mkdir(path.dirname(dest), { recursive: true });
            try { await pipeline(await f.open(), fs.createWriteStream(dest)); }
            catch (e) { await fsp.rm(dest, { force: true }); warn(`A file of plugin "${n}" was skipped: ${e.message}`); }
          }
          warn(`Plugin "${n}" is not enabled on this instance; its data was kept and will work once an admin installs and enables it.`);
        }
      }
    },
  };
  return api;
}

async function walk(dir, rel = '') {
  const out = [];
  for (const e of await fsp.readdir(path.join(dir, rel), { withFileTypes: true }).catch(() => [])) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...await walk(dir, r)); else if (e.isFile()) out.push(r);
  }
  return out;
}
export async function readAll(stream, cap) {
  const chunks = [];
  let n = 0;
  for await (const c of stream) { n += c.length; if (n > cap) { stream.destroy?.(); throw new Error('too large'); } chunks.push(c); }
  return Buffer.concat(chunks);
}

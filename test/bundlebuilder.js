// Hand-built greenroom bundles for tests and for the committed fixtures (scripts/make-fixtures.js).
// Deterministic: fixed timestamps and ids, so regenerating produces the same bytes.
import crypto from 'node:crypto';
import { ZipWriter } from '../src/zip.js';

export const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const T = (n) => `2025-03-0${n}T10:00:00.000Z`;

/** A valid history bundle; `mutate({doc, versions, entries})` may break it. Returns [{name, data}]. */
export function historyEntries(mutate) {
  const blobs = { index: Buffer.from('<h1>one</h1>'), css: Buffer.from('h1{color:red}'), two: Buffer.from('<h1>two</h1>') };
  const file = (path, b, type) => ({ path, sha256: sha(b), size: b.length, type });
  const versions = [
    { id: 'ver_fix1', number: 1, parent: null, author: 'Ada', author_id: 'usr_fixada', source: 'ui', message: 'First cut', created_at: T(1),
      files: [file('index.html', blobs.index, 'text/html; charset=utf-8'), file('a.css', blobs.css, 'text/css; charset=utf-8')] },
    { id: 'ver_fix2', number: 2, parent: 'ver_fix1', author: 'Claude (via Ada)', author_id: 'key_fixbot', source: 'mcp', message: 'Rewrite the heading', created_at: T(2),
      files: [file('index.html', blobs.two, 'text/html; charset=utf-8'), file('a.css', blobs.css, 'text/css; charset=utf-8')] },
  ];
  const doc = {
    format: 'greenroom-bundle/1', kind: 'history', exported_at: T(3), generator: { name: 'fixture', version: '1' },
    space: { id: 'spc_fix', slug: 'fixture', name: 'Fixture space', privacy: 'team', noindex: true, owner_id: 'usr_fixada', created_at: T(1), updated_at: T(2), live_version_id: 'ver_fix2', plugins: [] },
  };
  const entries = [{ name: 'space.json', data: null }, { name: 'history/versions.json', data: null }];
  for (const b of Object.values(blobs)) entries.push({ name: `history/blobs/${sha(b).slice(0, 2)}/${sha(b)}`, data: b });
  entries.push({ name: 'site/index.html', data: blobs.two }, { name: 'site/a.css', data: blobs.css });
  entries.push({ name: 'activity.json', data: JSON.stringify([{ actor_kind: 'session', actor_id: 'usr_fixada', action: 'version.created', resource_type: 'version', resource_id: 'ver_fix1', detail: { number: 1 }, created_at: T(1) }]) });
  mutate?.({ doc, versions, entries, blobs });
  entries[0].data = JSON.stringify(doc);
  if (entries[1].name === 'history/versions.json') entries[1].data = JSON.stringify(versions);
  return entries;
}

export function currentEntries(mutate) {
  const a = Buffer.from('<p>just the site</p>'), b = Buffer.from('');
  const doc = {
    format: 'greenroom-bundle/1', kind: 'current', exported_at: T(3), generator: { name: 'fixture', version: '1' },
    space: { id: 'spc_cur', slug: 'current-fixture', name: 'Current fixture', privacy: 'public', noindex: false, created_at: T(1), updated_at: T(2), live_version_id: 'ver_cur1', plugins: ['sqlite'] },
    live_version: { id: 'ver_cur1', number: 4, author: 'Claude (via Ada)', source: 'mcp', message: 'Latest', created_at: T(2) },
  };
  const entries = [{ name: 'space.json', data: null }, { name: 'site/index.html', data: a }, { name: 'site/empty.txt', data: b }, { name: 'plugins/sqlite/db.json', data: '{}' }];
  mutate?.({ doc, entries });
  entries[0].data = JSON.stringify(doc);
  return entries;
}

export async function writeZip(file, entries) {
  const z = new ZipWriter(file);
  for (const e of entries) await z.add(e.name, e.data);
  await z.finish();
}

// Regenerates test/fixtures/bundles/*.zip. Run: node scripts/make-fixtures.js
import fs from 'node:fs';
import { historyEntries, currentEntries, writeZip } from '../test/bundlebuilder.js';

const dir = new URL('../test/fixtures/bundles/', import.meta.url).pathname;
fs.mkdirSync(dir, { recursive: true });
await writeZip(dir + 'history.freespace-history.zip', historyEntries());
await writeZip(dir + 'current.freespace.zip', currentEntries());
// A second root commit mid-history: exercises `from 0000…` in the fast-import stream.
await writeZip(dir + 'restart.freespace-history.zip', historyEntries(({ versions }) => {
  versions.push({ ...versions[1], id: 'ver_fix3', number: 3, parent: null, message: 'Started over', created_at: '2025-03-03T10:00:00.000Z' });
  versions[2].files = [versions[0].files[0]];
}));
console.log('wrote', fs.readdirSync(dir).join(', '));

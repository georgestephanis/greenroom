#!/usr/bin/env node
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApp } from '../src/server.js';

const [cmd = 'serve', arg] = process.argv.slice(2);
// For a locked-out (or only) admin: run on the server, as the user that owns the data dir. Prints a one-time link.
if (cmd === 'reset-link' && arg) {
  const { loadConfig } = await import('../src/config.js'), { openDb } = await import('../src/db.js'), { mintToken, RESET_TTL } = await import('../src/people.js');
  const config = loadConfig(), db = openDb(config.dbFile);
  const u = db.prepare('SELECT * FROM users WHERE username = ? AND disabled_at IS NULL').get(arg.trim().toLowerCase());
  if (!u) { console.error(`No active user with email ${arg}`); process.exit(1); }
  const token = mintToken(db, 'reset', u.username, u.id, RESET_TTL);
  console.log(`${(config.publicUrl || `http://localhost:${config.port}`).replace(/\/$/, '')}/reset/${token}\n(valid 24 hours, works once)`);
  process.exit(0);
}
if (cmd !== 'serve') {
  console.error('Usage: greenroom serve\n       greenroom reset-link <email>');
  process.exit(cmd === 'help' ? 0 : 1);
}
// Extra plugins: GREENROOM_PLUGINS=/path/a.js,/path/b.js, each a module whose default export is a plugin.
const plugins = [];
for (const f of (process.env.GREENROOM_PLUGINS || '').split(',').filter(Boolean)) plugins.push((await import(pathToFileURL(path.resolve(f)))).default);
const { server, config } = createApp({ plugins });
server.listen(config.port, config.host, () => console.log(`greenroom listening on http://${config.host}:${config.port}`));

#!/usr/bin/env node
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApp } from '../src/server.js';

const [cmd = 'serve'] = process.argv.slice(2);
if (cmd !== 'serve') {
  console.error(`Usage: freespace serve\n(publishing from the CLI arrives with agent tokens in a later milestone)`);
  process.exit(cmd === 'help' ? 0 : 1);
}
// Extra plugins: FREESPACE_PLUGINS=/path/a.js,/path/b.js, each a module whose default export is a plugin.
const plugins = [];
for (const f of (process.env.FREESPACE_PLUGINS || '').split(',').filter(Boolean)) plugins.push((await import(pathToFileURL(path.resolve(f)))).default);
const { server, config } = createApp({ plugins });
server.listen(config.port, config.host, () => console.log(`freespace listening on http://${config.host}:${config.port}`));

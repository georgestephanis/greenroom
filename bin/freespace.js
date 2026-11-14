#!/usr/bin/env node
import { createApp } from '../src/server.js';

const [cmd = 'serve'] = process.argv.slice(2);
if (cmd !== 'serve') {
  console.error(`Usage: freespace serve\n(publishing from the CLI arrives with agent tokens in a later milestone)`);
  process.exit(cmd === 'help' ? 0 : 1);
}
const { server, config } = createApp();
server.listen(config.port, config.host, () => console.log(`freespace listening on http://${config.host}:${config.port}`));

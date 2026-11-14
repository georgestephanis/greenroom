import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';

test('boots with a 256 MB heap cap and stays far under a 1 GB budget', async (x) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gr-boot-'));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, ['--max-old-space-size=256', path.resolve('bin/greenroom.js'), 'serve'], {
    env: { ...process.env, GREENROOM_DATA_DIR: dir, PORT: String(port) }, stdio: ['ignore', 'pipe', 'inherit'],
  });
  x.after(() => { child.kill(); fs.rmSync(dir, { recursive: true, force: true }); });
  await new Promise((r) => child.stdout.once('data', r));
  const res = await fetch(`http://127.0.0.1:${port}/login`);
  assert.equal(res.status, 200);
  const rssMb = Number(execFileSync('ps', ['-o', 'rss=', '-p', String(child.pid)]).toString()) / 1024;
  assert.ok(rssMb < 150, `RSS ${rssMb.toFixed(0)} MB`);
});

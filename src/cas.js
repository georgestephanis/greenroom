// Content-addressed blobs. Same on-disk layout as Spacefast: {blobsDir}/{ab}/{sha256}.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream/promises';

const HASH = /^[a-f0-9]{64}$/;

export class CAS {
  constructor(baseDir, tmpDir) {
    this.baseDir = baseDir;
    this.tmpDir = tmpDir;
    fs.mkdirSync(baseDir, { recursive: true });
    fs.mkdirSync(tmpDir, { recursive: true });
  }
  path(sha) {
    sha = String(sha).toLowerCase();
    if (!HASH.test(sha)) throw new Error(`invalid sha256: ${sha}`);
    return path.join(this.baseDir, sha.slice(0, 2), sha);
  }
  has(sha) { return fs.existsSync(this.path(sha)); }
  size(sha) { try { return fs.statSync(this.path(sha)).size; } catch { return null; } }
  read(sha) { return fsp.readFile(this.path(sha)); }
  stream(sha, opts) { return fs.createReadStream(this.path(sha), opts); }
  /** Refresh mtime so GC's grace period protects a blob a new version is about to reference. */
  touch(sha) { try { const t = new Date(); fs.utimesSync(this.path(sha), t, t); return true; } catch { return false; } }

  async #commit(tmp, sha) {
    const final = this.path(sha);
    if (this.touch(sha)) return fsp.unlink(tmp);
    await fsp.mkdir(path.dirname(final), { recursive: true });
    await fsp.rename(tmp, final);
  }
  async storeBuffer(buf) {
    const sha = crypto.createHash('sha256').update(buf).digest('hex');
    if (!this.touch(sha)) {
      const tmp = path.join(this.tmpDir, `buf-${sha}-${crypto.randomUUID()}`);
      await fsp.writeFile(tmp, buf);
      await this.#commit(tmp, sha);
    }
    return { sha256: sha, size: buf.length };
  }
  /** Stream into CAS without buffering. `maxBytes` aborts oversized input. */
  async storeStream(readable, maxBytes = Infinity) {
    const tmp = path.join(this.tmpDir, `str-${crypto.randomUUID()}`);
    const h = crypto.createHash('sha256');
    let size = 0;
    readable.on('data', (c) => {
      h.update(c);
      size += c.length;
      if (size > maxBytes) readable.destroy(new Error('file too large'));
    });
    try {
      await pipeline(readable, fs.createWriteStream(tmp));
    } catch (e) {
      await fsp.unlink(tmp).catch(() => {});
      throw e;
    }
    const sha = h.digest('hex');
    await this.#commit(tmp, sha);
    return { sha256: sha, size };
  }
  /** Delete blobs not in `active` and older than the grace period; sweep stale temp files.
   *  `stillUsed(sha)` re-checks each candidate just before unlinking, since `active` is a snapshot. */
  async gc(active, graceMs = 3600e3, stillUsed = () => false) {
    const cutoff = Date.now() - graceMs;
    let removed = 0, freed = 0;
    for (const shard of await fsp.readdir(this.baseDir).catch(() => [])) {
      if (!/^[a-f0-9]{2}$/.test(shard)) continue;
      for (const f of await fsp.readdir(path.join(this.baseDir, shard))) {
        if (!HASH.test(f) || active.has(f)) continue;
        const p = path.join(this.baseDir, shard, f);
        const st = await fsp.stat(p).catch(() => null);
        if (st && st.mtimeMs < cutoff && !stillUsed(f)) { await fsp.unlink(p); removed++; freed += st.size; }
      }
    }
    for (const f of await fsp.readdir(this.tmpDir).catch(() => [])) {
      const p = path.join(this.tmpDir, f);
      const st = await fsp.stat(p).catch(() => null);
      if (st && st.mtimeMs < cutoff) { await fsp.unlink(p).catch(() => {}); removed++; freed += st.size; }
    }
    return { removed, freed };
  }
}

// Zip import that streams each entry straight into CAS (nothing is buffered whole).
// Reads the central directory from the file on disk; refuses encryption and zip64.
import fs from 'node:fs';
import zlib from 'node:zlib';
import { Readable } from 'node:stream';
import { finished } from 'node:stream/promises';
import { once } from 'node:events';
import { httpErr } from './auth.js';
import { cleanPath, contentType } from './util.js';

export const MAX_ENTRIES = 5000;
const MAX_CD = 8 * 1024 * 1024;

async function readAt(fh, pos, len) {
  const buf = Buffer.alloc(len);
  const { bytesRead } = await fh.read(buf, 0, len, pos);
  return buf.subarray(0, bytesRead);
}

/**
 * Opens a zip on disk, validates its central directory, and calls fn({ raw, open }).
 * `raw` is [{name, method, csize, usize, off}] (directories, __MACOSX and .DS_Store are dropped);
 * `open(entry)` resolves to a stream of that entry's inflated bytes. Nothing is read whole.
 */
export async function withZip(file, { maxEntries = MAX_ENTRIES, maxCd = MAX_CD } = {}, fn) {
  const fh = await fs.promises.open(file, 'r');
  try {
    const size = (await fh.stat()).size;
    const tail = await readAt(fh, Math.max(0, size - 65557), Math.min(size, 65557));
    const eocd = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (eocd < 0) throw httpErr(400, 'Not a zip file');
    const count = tail.readUInt16LE(eocd + 10), cdSize = tail.readUInt32LE(eocd + 12), cdOff = tail.readUInt32LE(eocd + 16);
    if (count === 0xffff || cdOff === 0xffffffff) throw httpErr(400, 'zip64 archives are not supported');
    if (count > maxEntries || cdSize > maxCd) throw httpErr(413, 'Archive has too many entries');
    const cd = await readAt(fh, cdOff, cdSize);

    const raw = [];
    try {
      for (let pos = 0, i = 0; i < count; i++) {
        if (cd.readUInt32LE(pos) !== 0x02014b50) throw httpErr(400, 'Corrupt zip directory');
        const flags = cd.readUInt16LE(pos + 8), method = cd.readUInt16LE(pos + 10);
        const csize = cd.readUInt32LE(pos + 20), usize = cd.readUInt32LE(pos + 24);
        const nlen = cd.readUInt16LE(pos + 28), xlen = cd.readUInt16LE(pos + 30), clen = cd.readUInt16LE(pos + 32);
        const off = cd.readUInt32LE(pos + 42);
        const name = cd.toString('utf8', pos + 46, pos + 46 + nlen);
        pos += 46 + nlen + xlen + clen;
        if (name.endsWith('/') || name.startsWith('__MACOSX/') || name.endsWith('.DS_Store')) continue;
        if (flags & 1) throw httpErr(400, 'Encrypted archives are not supported');
        if (method !== 0 && method !== 8) throw httpErr(400, `Unsupported compression in ${name}`);
        raw.push({ name, method, csize, usize, off });
      }
    } catch (e) {
      throw e.status ? e : httpErr(400, 'Corrupt zip directory');
    }

    const open = async (r) => {
      const lh = await readAt(fh, r.off, 30);
      if (lh.length < 30 || lh.readUInt32LE(0) !== 0x04034b50) throw httpErr(400, 'Corrupt zip entry');
      const start = r.off + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
      // createReadStream throws on an empty range (end < start), so an empty entry gets an empty stream.
      let src = r.csize ? fs.createReadStream(file, { start, end: start + r.csize - 1 }) : Readable.from([]);
      if (r.method === 8) {
        const inf = zlib.createInflateRaw();
        src.on('error', (e) => inf.destroy(e));
        src.pipe(inf);
        src = inf;
      }
      return src;
    };
    return await fn({ raw, open });
  } finally {
    await fh.close();
  }
}

/** Returns Map(path -> {path, sha256, size, content_type}). */
export function importZip(file, cas, { maxFileBytes, maxSpaceBytes }) {
  return withZip(file, {}, async ({ raw, open }) => {
    // Folders zipped from Finder/`zip -r dir` carry one shared top-level directory; drop it.
    const tops = new Set(raw.map((r) => r.name.split('/')[0]));
    const strip = tops.size === 1 && ![...tops][0].match(/^\.{0,2}$/) && raw.every((r) => r.name.includes('/')) ? [...tops][0] + '/' : '';

    const entries = new Map();
    let total = 0;
    for (const r of raw) {
      const p = cleanPath(strip ? r.name.slice(strip.length) : r.name);
      if (!p) throw httpErr(400, `Unsafe path in archive: ${r.name}`);
      if (entries.has(p)) throw httpErr(400, `Duplicate path in archive: ${p}`);
      if (r.usize > maxFileBytes) throw httpErr(413, `File too large: ${p}`);
      const src = await open(r);
      // Bounded by the *actual* inflated size, not the declared one (zip bombs).
      let stored;
      try {
        stored = await cas.storeStream(src, Math.min(maxFileBytes, maxSpaceBytes - total));
      } catch (e) {
        throw httpErr(413, `Could not store ${p}: ${e.message}`);
      }
      total += stored.size;
      entries.set(p, { path: p, ...stored, content_type: contentType(p) });
    }
    return entries;
  });
}

const MS_DOS_EPOCH = { time: 0, date: (0 << 9) | (1 << 5) | 1 }; // 1980-01-01, so exports are reproducible

/**
 * Streaming zip writer: each entry is deflated straight to disk with a data descriptor, so memory
 * stays flat whatever the size. No zip64 (our reader refuses it too): a 4 GiB archive is an error.
 */
export class ZipWriter {
  constructor(file) {
    this.out = fs.createWriteStream(file);
    this.out.on('error', (e) => { this.err ??= e; });
    this.off = 0;
    this.cd = [];
    this.names = new Set();
  }
  async #w(buf) {
    if (this.err) throw this.err;
    this.off += buf.length;
    if (this.off > 0xfffffff0) throw new Error('export is too large for a zip (no zip64)');
    if (!this.out.write(buf)) await once(this.out, 'drain');
  }
  /** `source` is a Buffer, or an (async) iterable of Buffers. */
  async add(name, source, { deflate = true } = {}) {
    if (this.names.has(name)) throw new Error(`duplicate zip entry ${name}`);
    this.names.add(name);
    const nm = Buffer.from(name), off = this.off, method = deflate ? 8 : 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0808, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(MS_DOS_EPOCH.time, 10); lh.writeUInt16LE(MS_DOS_EPOCH.date, 12); lh.writeUInt16LE(nm.length, 26);
    await this.#w(lh); await this.#w(nm);
    let crc = 0, usize = 0, csize = 0;
    async function* raw() {
      for await (const c of Buffer.isBuffer(source) ? [source] : source) {
        const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
        crc = zlib.crc32(b, crc); usize += b.length;
        yield b;
      }
    }
    let body = Readable.from(raw());
    if (deflate) {
      const def = zlib.createDeflateRaw();
      body.on('error', (e) => def.destroy(e));
      body.pipe(def);
      body = def;
    }
    for await (const c of body) { csize += c.length; await this.#w(c); }
    if (usize > 0xffffffff) throw new Error(`${name} is too large for a zip (no zip64)`);
    const dd = Buffer.alloc(16);
    dd.writeUInt32LE(0x08074b50, 0); dd.writeUInt32LE(crc, 4); dd.writeUInt32LE(csize, 8); dd.writeUInt32LE(usize, 12);
    await this.#w(dd);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(0x031e, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0808, 8); ch.writeUInt16LE(method, 10);
    ch.writeUInt16LE(MS_DOS_EPOCH.time, 12); ch.writeUInt16LE(MS_DOS_EPOCH.date, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(csize, 20); ch.writeUInt32LE(usize, 24); ch.writeUInt16LE(nm.length, 28);
    ch.writeUInt32LE((0o100644 << 16) >>> 0, 38); ch.writeUInt32LE(off, 42);
    this.cd.push(ch, nm);
  }
  async finish() {
    const cd = Buffer.concat(this.cd), n = this.names.size;
    if (n >= 0xffff) throw new Error('too many entries for a zip (no zip64)');
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(n, 8); end.writeUInt16LE(n, 10);
    end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(this.off, 16);
    await this.#w(cd); await this.#w(end);
    this.out.end();
    await finished(this.out);
  }
  /** Abandon a half-written archive. */
  abort() { this.out.destroy(); }
}

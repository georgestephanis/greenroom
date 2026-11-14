// Zip import that streams each entry straight into CAS (nothing is buffered whole).
// Reads the central directory from the file on disk; refuses encryption and zip64.
import fs from 'node:fs';
import zlib from 'node:zlib';
import { httpErr } from './auth.js';
import { cleanPath, contentType } from './util.js';

const MAX_ENTRIES = 5000;
const MAX_CD = 8 * 1024 * 1024;

async function readAt(fh, pos, len) {
  const buf = Buffer.alloc(len);
  const { bytesRead } = await fh.read(buf, 0, len, pos);
  return buf.subarray(0, bytesRead);
}

/** Returns Map(path -> {path, sha256, size, content_type}). */
export async function importZip(file, cas, { maxFileBytes, maxSpaceBytes }) {
  const fh = await fs.promises.open(file, 'r');
  try {
    const size = (await fh.stat()).size;
    const tail = await readAt(fh, Math.max(0, size - 65557), Math.min(size, 65557));
    const eocd = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (eocd < 0) throw httpErr(400, 'Not a zip file');
    const count = tail.readUInt16LE(eocd + 10), cdSize = tail.readUInt32LE(eocd + 12), cdOff = tail.readUInt32LE(eocd + 16);
    if (count === 0xffff || cdOff === 0xffffffff) throw httpErr(400, 'zip64 archives are not supported');
    if (count > MAX_ENTRIES || cdSize > MAX_CD) throw httpErr(413, 'Archive has too many entries');
    const cd = await readAt(fh, cdOff, cdSize);

    const raw = [];
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
      const lh = await readAt(fh, r.off, 30);
      if (lh.readUInt32LE(0) !== 0x04034b50) throw httpErr(400, 'Corrupt zip entry');
      const start = r.off + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
      let src = fs.createReadStream(file, { start, end: start + r.csize - 1 });
      if (r.method === 8) {
        const inf = zlib.createInflateRaw();
        src.on('error', (e) => inf.destroy(e));
        src.pipe(inf);
        src = inf;
      }
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
  } finally {
    await fh.close();
  }
}

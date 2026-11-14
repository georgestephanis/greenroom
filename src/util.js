import crypto from 'node:crypto';

export const now = () => new Date().toISOString();
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
// homefast prefixed ids: spc_, ver_, usr_, ses_, grt_ ... (nanoid-style, 20 chars)
export function newId(prefix, len = 20) {
  const b = crypto.randomBytes(len);
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[b[i] % ALPHABET.length];
  return `${prefix}_${s}`;
}
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
export const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest('base64url');
export function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

const TYPES = {
  html: 'text/html', htm: 'text/html', css: 'text/css', js: 'text/javascript', mjs: 'text/javascript',
  json: 'application/json', txt: 'text/plain', md: 'text/markdown', csv: 'text/csv', xml: 'application/xml',
  svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', avif: 'image/avif', ico: 'image/x-icon', pdf: 'application/pdf',
  woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf', mp4: 'video/mp4',
  webm: 'video/webm', mp3: 'audio/mpeg', wav: 'audio/wav', wasm: 'application/wasm', map: 'application/json',
};
export function contentType(p) {
  const ext = p.split('.').pop().toLowerCase();
  const t = TYPES[ext] || 'application/octet-stream';
  return /^text\/|json$|xml$|javascript$|svg/.test(t) ? `${t}; charset=utf-8` : t;
}

export const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?$/;
export function slugify(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50) || 'space';
}
// Normalise a manifest path: forward slashes, no leading slash, no traversal. Returns null if unsafe.
export function cleanPath(p) {
  if (typeof p !== 'string' || p.includes('\0') || p.includes('\\')) return null;
  const parts = p.split('/').filter((x) => x !== '' && x !== '.');
  if (!parts.length || parts.some((x) => x === '..')) return null;
  return parts.join('/');
}
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

// Path-mode security (issue #214 section 4). Everything here is pure and unit-tested; the server
// calls into it so no response under /s/ can bypass it.
import { hmac, safeEqual } from './util.js';
import { FORBIDDEN_HEADER_NAMES } from './routing.js';

// Rule 1: every response under /s/ is sandboxed => each document gets an opaque origin.
// allow-same-origin, allow-popups-to-escape-sandbox and allow-top-navigation are never granted.
export const SPACE_CSP = 'sandbox allow-scripts allow-forms allow-popups allow-modals allow-downloads';

export function applySpaceHeaders(res, { noindex = true } = {}) {
  res.setHeader('Content-Security-Policy', SPACE_CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (noindex) res.setHeader('X-Robots-Tag', 'noindex');
}

export const DASHBOARD_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
  "frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

export function applyDashboardHeaders(res) {
  res.setHeader('Content-Security-Policy', DASHBOARD_CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cache-Control', 'no-store');
}

// Rule 2: tenant-controlled headers (_headers, plugin responses) can never touch these.
export function isReservedHeader(name) {
  const n = String(name).toLowerCase();
  return FORBIDDEN_HEADER_NAMES.has(n) || n.startsWith('cross-origin-') || n.startsWith('access-control-');
}
export function filterTenantHeaders(headers) {
  const kept = {}, dropped = [];
  for (const [k, v] of Object.entries(headers)) {
    if (isReservedHeader(k)) dropped.push(k);
    else kept[k] = v;
  }
  return { kept, dropped };
}

// Rule 5: plugin cookies are pinned to one space and prefixed so they cannot collide with ours.
const RESERVED_COOKIE = /^(__host-|__secure-|fs_|fsv_|fsp_)/i;
export function rewriteSetCookie(values, space) {
  const out = [];
  for (const raw of [].concat(values ?? [])) {
    const parts = String(raw).split(';').map((s) => s.trim());
    const eq = parts[0].indexOf('=');
    if (eq < 1) continue;
    const name = parts[0].slice(0, eq), value = parts[0].slice(eq + 1);
    if (RESERVED_COOKIE.test(name)) continue;
    const keep = parts.slice(1).filter((a) => /^(max-age|expires|httponly)\b/i.test(a));
    out.push([`fsp_${space.id.slice(4, 12)}_${name}=${value}`, `Path=/s/${space.slug}/`, 'Secure', 'SameSite=None', ...keep].join('; '));
  }
  return out;
}

// Rule 6: viewer cookies are bound to ONE space id by HMAC. Path is a convenience, not the boundary.
export const viewerCookieName = (space) => `fsv_${space.id.slice(4, 12)}`;

export function signViewer(secret, space, subject, ttlMs, kind = 'team') {
  const exp = Date.now() + ttlMs;
  const body = `${space.id}.${kind}.${subject}.${exp}`;
  return { value: `${body}.${hmac(secret, `viewer:${body}`)}`, exp };
}
/** Returns { kind, subject } when the cookie is valid for exactly this space, else null. */
export function verifyViewer(secret, space, value) {
  const i = (value || '').lastIndexOf('.');
  if (i < 1) return null;
  const body = value.slice(0, i);
  if (!safeEqual(value.slice(i + 1), hmac(secret, `viewer:${body}`))) return null;
  const [spaceId, kind, subject, exp] = body.split('.');
  if (spaceId !== space.id || Number(exp) < Date.now()) return null;
  return { kind, subject };
}
export function viewerSetCookie(space, signed) {
  const maxAge = Math.max(0, Math.floor((signed.exp - Date.now()) / 1000));
  return `${viewerCookieName(space)}=${signed.value}; Path=/s/${space.slug}/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAge}`;
}

// Rule 7: per-document token for data-API writes. Short-lived, bound to one space, only readable by
// the document it was injected into (a <meta> tag). Used by the sqlite plugin (M5).
export function signDocToken(secret, space, ttlMs = 10 * 60e3) {
  const body = `${space.id}.${Date.now() + ttlMs}`;
  return `${body}.${hmac(secret, `doc:${body}`)}`;
}
export function verifyDocToken(secret, space, token) {
  const i = (token || '').lastIndexOf('.');
  if (i < 1) return false;
  const body = token.slice(0, i);
  if (!safeEqual(token.slice(i + 1), hmac(secret, `doc:${body}`))) return false;
  const [spaceId, exp] = body.split('.');
  return spaceId === space.id && Number(exp) >= Date.now();
}
export function injectDocToken(html, token) {
  const tag = `<meta name="freespace-doc-token" content="${token}">`;
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, (m) => m + tag) : tag + html;
}
export const isDocumentRequest = (req) => ['document', 'iframe'].includes(req.headers['sec-fetch-dest']);

// Rule 4: writes need Sec-Fetch-Site: same-origin and a CSRF token; Origin: null is rejected outright.
// Bearer-authenticated requests are exempt (they carry no ambient cookie).
export function checkWrite(req, cred, body) {
  if (req.headers.origin === 'null') return 'Origin: null is not allowed';
  // resolve() uses only the Bearer header when present, so no ambient cookie is in play.
  if (cred?.via === 'bearer' || /^Bearer /.test(req.headers.authorization || '')) return null;
  const site = req.headers['sec-fetch-site'];
  if (cred) {
    if (site !== 'same-origin') return 'Cross-site request refused';
    const token = req.headers['x-csrf-token'] ?? body?._csrf;
    if (!token || !safeEqual(token, cred.csrf)) return 'Missing or invalid CSRF token';
  } else if (site && site !== 'same-origin') {
    return 'Cross-site request refused';
  }
  return null;
}

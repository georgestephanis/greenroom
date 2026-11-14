// Outbound fetch for client metadata documents (CIMD), ported from homefast core/src/engine/ssrf.ts.
// Every resolved address is checked inside the socket's own lookup, so a DNS answer that flips to a
// private address between check and connect is never reached (no rebinding window).
import dns from 'node:dns';
import net from 'node:net';
import https from 'node:https';

function isPrivateIpv4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 0 && ip.split('.')[2] === '0') || (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) || a >= 224;
}

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateIpv4(ip);
  if (!net.isIPv6(ip)) return true;
  const s = ip.toLowerCase();
  const mapped = /^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (mapped) return isPrivateIpv4(mapped[1]);
  // Embedded-IPv4 forms (mapped, NAT64 incl. local-use 64:ff9b:1::/48, 6to4 2002::/16): fail closed.
  if (s.startsWith('::ffff:') || s.startsWith('64:ff9b:') || s.startsWith('2002:')) return true;
  return s === '::1' || s === '::' || /^f[cd]/.test(s) || /^fe[89ab]/.test(s) || /^fe[c-f]/.test(s) || s.startsWith('ff');
}

export function guardedLookup(hostname, options, cb) {
  const all = typeof options === 'object' && options?.all;
  const done = (list) => {
    const bad = list.find((a) => isPrivateIp(a.address));
    if (bad) return cb(Object.assign(new Error(`Blocked private address ${bad.address}`), { code: 'EACCES' }));
    return all ? cb(null, list) : cb(null, list[0].address, list[0].family);
  };
  if (net.isIP(hostname)) return done([{ address: hostname, family: net.isIPv6(hostname) ? 6 : 4 }]);
  dns.lookup(hostname, { all: true }, (err, list) => (err ? cb(err) : done(list)));
}

/** GET an https URL as JSON: public addresses only, no redirects, size- and time-limited. */
// `timeoutMs` bounds the whole fetch, not just idle gaps: a host trickling a byte at a time can't hold
// the consent page open. `tls` is for tests only (a local CA and lookup); production passes nothing.
export function fetchJson(url, { maxBytes = 64 * 1024, timeoutMs = 5000, tls = {} } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (u.protocol !== 'https:' || /^(localhost|.*\.localhost|.*\.local)$/i.test(u.hostname)) return reject(new Error('Client metadata must be on a public https host'));
    const literal = u.hostname.replace(/^\[|\]$/g, ''); // Node never calls lookup for IP literals, so check them here
    if (net.isIP(literal) && isPrivateIp(literal)) return reject(new Error(`Blocked private address ${literal}`));
    const req = https.request(u, { method: 'GET', lookup: guardedLookup, ...tls, headers: { accept: 'application/json' } }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`Client metadata returned HTTP ${res.statusCode}`)); }
      const chunks = []; let n = 0;
      res.on('data', (c) => { n += c.length; if (n > maxBytes) req.destroy(new Error('Client metadata too large')); else chunks.push(c); });
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('Client metadata is not JSON')); } });
      res.on('error', reject);
    });
    const deadline = setTimeout(() => req.destroy(new Error('Client metadata fetch timed out')), timeoutMs);
    req.on('close', () => clearTimeout(deadline));
    req.on('error', reject);
    req.end();
  });
}

// Minimal SMTP client (issue #214 section 6): implicit TLS or STARTTLS, AUTH PLAIN, plain-text mail.
// No dependencies. Every step has an idle timeout; a header value with CR or LF is refused outright.
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
export const isLoopback = (host) => LOOPBACK.has(String(host).toLowerCase());

export function cleanHeader(v) {
  const s = String(v ?? '');
  if (/[\r\n]/.test(s)) throw Object.assign(new Error('Header values cannot contain line breaks'), { status: 400 });
  return s;
}
// RFC 2047 for non-ASCII subjects; ASCII passes through untouched.
const encodeWord = (s) => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${Buffer.from(s).toString('base64')}?=`);

/** CRLF line endings, then RFC 5321 4.5.2 dot-stuffing, then the terminating dot. */
export const dotStuff = (text) => `${String(text).replace(/\r\n|\r|\n/g, '\r\n').replace(/^\./gm, '..')}\r\n.\r\n`;

/**
 * smtp: { host, port, security: 'tls' | 'starttls' | 'none', user, pass, from, helo }.
 * 'none' is only for a relay on this machine; credentials never cross the network in clear.
 */
export async function sendMail(smtp, { to, subject, text }, timeoutMs = 15_000) {
  const [from, rcpt, subj, host, helo] = [smtp.from, to, subject, smtp.host, smtp.helo || 'greenroom'].map(cleanHeader);
  cleanHeader(smtp.user);
  if (smtp.security === 'none' && !isLoopback(host)) throw new Error('Unencrypted SMTP is only allowed to a relay on this machine');
  let sock = smtp.security === 'tls' ? tls.connect({ host, port: smtp.port, servername: host }) : net.connect({ host, port: smtp.port });
  let buf = '', wait = null, err = null;
  const flush = () => {
    if (!wait) return;
    const lines = buf.split('\r\n');
    const i = lines.slice(0, -1).findIndex((l) => /^\d{3}(?: |$)/.test(l)); // last line of a (multi-line) reply
    if (i >= 0) {
      buf = lines.slice(i + 1).join('\r\n');
      const w = wait; wait = null;
      w.ok({ code: +lines[i].slice(0, 3), text: lines.slice(0, i + 1).join('\n') });
    } else if (err || buf.length > 65536) { const w = wait; wait = null; w.fail(err || new Error('SMTP reply too long')); }
  };
  const attach = (s) => {
    s.setTimeout(timeoutMs, () => s.destroy(new Error('SMTP timeout')));
    s.on('data', (d) => { buf += d.toString('latin1'); flush(); });
    s.on('error', (e) => { err ??= e; flush(); });
    s.on('close', () => { err ??= new Error('SMTP connection closed'); flush(); });
  };
  const reply = (want) => new Promise((ok, fail) => { wait = { ok, fail }; flush(); }).then((r) => {
    if (!want.includes(r.code)) throw new Error(`SMTP ${r.code}: ${r.text.split('\n').pop().slice(4, 200)}`);
    return r;
  });
  const cmd = (line, want) => { sock.write(line + '\r\n'); return reply(want); };
  attach(sock);
  try {
    await reply([220]);
    let ehlo = await cmd(`EHLO ${helo}`, [250]);
    if (smtp.security === 'starttls') {
      if (!/^250[- ]STARTTLS\b/im.test(ehlo.text)) throw new Error('Server does not offer STARTTLS');
      await cmd('STARTTLS', [220]);
      buf = '';
      sock.removeAllListeners('data');
      sock = tls.connect({ socket: sock, servername: host });
      attach(sock);
      await new Promise((ok, fail) => { sock.once('secureConnect', ok); sock.once('error', fail); });
      ehlo = await cmd(`EHLO ${helo}`, [250]);
    }
    if (smtp.user) await cmd(`AUTH PLAIN ${Buffer.from(`\0${smtp.user}\0${smtp.pass ?? ''}`).toString('base64')}`, [235]);
    await cmd(`MAIL FROM:<${from}>`, [250]);
    await cmd(`RCPT TO:<${rcpt}>`, [250, 251]);
    await cmd('DATA', [354]);
    const head = [`From: ${from}`, `To: ${rcpt}`, `Subject: ${encodeWord(subj)}`, `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
      `Message-ID: <${crypto.randomUUID()}@${from.split('@')[1]}>`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit'];
    sock.write(dotStuff(`${head.join('\r\n')}\r\n\r\n${text}`));
    await reply([250]);
    sock.write('QUIT\r\n');
  } finally {
    sock.end();
  }
}

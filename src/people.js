// People (issue #214 section 6, M6): SMTP settings, domain self-signup and email re-confirmation.
// Offboarding needs nothing here: Auth.activeUser is the live constraint every credential resolves through.
import crypto from 'node:crypto';
import { httpErr } from './auth.js';
import { sendMail, cleanHeader, isLoopback } from './mail.js';
import { normDomain, normEmail, now, randomToken, sha256hex } from './util.js';

const LINK_TTL = 30 * 60e3;
const SECURITY = ['tls', 'starttls', 'none'];

export class People {
  constructor({ db, auth, store, config, throttle, send = sendMail }) {
    Object.assign(this, { db, auth, store, config, throttle, send });
    const row = db.prepare("SELECT value FROM meta WHERE key = 'people'").get();
    this.s = { smtp: null, signup: false, domains: [], reconfirmDays: 0, reconfirmSince: null, origin: '', ...(row ? JSON.parse(row.value) : {}) };
    this.#sync();
  }

  // The SMTP password is encrypted at rest with a key derived from the instance secret (secret.key, mode 0600),
  // so a copy of control.db alone does not reveal it. It is never sent back to the browser or logged.
  #key() { return Buffer.from(crypto.hkdfSync('sha256', this.config.secret, '', 'greenroom smtp password', 32)); }
  #seal(pw) {
    const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', this.#key(), iv);
    const ct = Buffer.concat([c.update(pw, 'utf8'), c.final()]);
    return [iv, c.getAuthTag(), ct].map((b) => b.toString('base64url')).join('.');
  }
  #open(sealed) {
    if (!sealed) return '';
    const [iv, tag, ct] = sealed.split('.').map((x) => Buffer.from(x, 'base64url'));
    const d = crypto.createDecipheriv('aes-256-gcm', this.#key(), iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  }
  #save() {
    this.db.prepare("INSERT INTO meta (key,value) VALUES ('people',?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(JSON.stringify(this.s));
    this.#sync();
  }
  // Re-confirmation only bites while mail can be sent; without SMTP nobody could ever restore access.
  #sync() { this.auth.reconfirm = this.s.smtp && this.s.reconfirmDays > 0 ? { days: this.s.reconfirmDays, since: this.s.reconfirmSince } : null; }

  signupOpen() { return !!(this.s.signup && this.s.smtp && this.s.domains.length); }
  /** What the Instance page shows. The password is reduced to "one is set". */
  view() {
    const m = this.s.smtp;
    return { smtp: m && { host: m.host, port: m.port, security: m.security, user: m.user, from: m.from, hasPass: !!m.pass }, signup: this.s.signup, signupOpen: this.signupOpen(), domains: this.s.domains, reconfirmDays: this.s.reconfirmDays };
  }

  setSmtp(cred, b, origin) {
    if (b.clear === '1' || b.clear === true) {
      this.s.smtp = null;
      this.#save();
      this.store.log(cred, 'smtp.cleared', null);
      return;
    }
    const host = cleanHeader(b.host).trim().toLowerCase(), port = Number(b.port), security = String(b.security || '');
    if (!/^[a-z0-9.-]+$|^\[[0-9a-f:.]+\]$/.test(host)) throw httpErr(400, 'Enter a valid SMTP host');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw httpErr(400, 'Enter a valid port');
    if (!SECURITY.includes(security)) throw httpErr(400, 'Choose implicit TLS or STARTTLS');
    if (security === 'none' && !isLoopback(host)) throw httpErr(400, 'Unencrypted SMTP is only allowed to a relay on this machine');
    const from = normEmail(cleanHeader(b.from));
    if (!from) throw httpErr(400, 'Enter a valid from-address');
    const user = cleanHeader(b.user).trim().slice(0, 200);
    const prev = this.s.smtp;
    // Blank keeps the stored password, but only for the same server: otherwise a hijacked session could
    // point the saved credentials at a server it controls.
    if (!b.pass && user && prev?.pass && (prev.host !== host || prev.port !== port || prev.security !== security || prev.user !== user)) throw httpErr(400, 'Re-enter the password when changing the server or username');
    const pass = b.pass ? this.#seal(String(b.pass)) : user ? prev?.pass ?? null : null;
    if (!prev && this.s.reconfirmDays) this.s.reconfirmSince = now(); // re-confirmation comes back on: a fresh N days
    this.s.smtp = { host, port, security, user, from, pass };
    // Links in mail point here: GREENROOM_PUBLIC_URL, else the origin the admin saved these settings from,
    // never the Host header of the request that triggers a mail (a forged Host would steal signup links).
    this.s.origin = this.config.publicUrl || origin;
    this.#save();
    this.store.log(cred, 'smtp.updated', null, { host, port, security });
  }
  #smtp() { const m = this.s.smtp; return m && { ...m, pass: this.#open(m.pass), helo: new URL(this.#origin()).hostname }; }
  #origin() { return (this.config.publicUrl || this.s.origin).replace(/\/$/, ''); }

  /** Awaited: the admin sees the server's answer. */
  async test(cred) {
    if (!this.s.smtp) throw httpErr(400, 'Save SMTP settings first');
    try { await this.send(this.#smtp(), { to: cred.user.username, subject: 'greenroom test email', text: 'SMTP is working. This message was sent from the Instance page.\n' }); }
    catch (e) { throw httpErr(400, `Sending failed: ${e.message}`); }
    this.store.log(cred, 'smtp.tested', null);
  }
  /** Fire and forget: a request never waits on (or reveals timing through) the mail server. */
  #mail(to, subject, text) {
    const m = this.#smtp();
    if (!m) return;
    this.send(m, { to, subject, text }).catch((e) => console.error(`greenroom: mail not sent: ${e.message}`));
  }

  setSignup(cred, b) {
    const on = b.enabled === '1' || b.enabled === true;
    if (on && !this.s.smtp) throw httpErr(400, 'Configure SMTP before turning on self-signup');
    const raw = Array.isArray(b.domains) ? b.domains : String(b.domains ?? '').split(/[\s,]+/);
    const domains = [];
    for (const d of raw.filter(Boolean)) {
      const n = normDomain(d);
      if (!n) throw httpErr(400, `Not a domain: ${String(d).slice(0, 100)}`);
      if (!domains.includes(n)) domains.push(n);
    }
    Object.assign(this.s, { signup: on, domains });
    this.#save();
    this.store.log(cred, 'signup.settings', null, { enabled: on, domains });
  }

  setReconfirm(cred, b) {
    const days = Number(b.days || 0);
    if (!Number.isInteger(days) || days < 0 || days > 3650) throw httpErr(400, 'Days must be a whole number from 0 (off) to 3650');
    if (days && !this.s.smtp) throw httpErr(400, 'Configure SMTP before turning on re-confirmation');
    // Turning it on starts everyone's clock now, so nobody is locked out the moment it is enabled.
    // Lowering N likewise restarts it, so a shorter period never lapses people (or the acting admin) on the spot.
    if (days && (!this.s.reconfirmDays || days < this.s.reconfirmDays)) this.s.reconfirmSince = now();
    this.s.reconfirmDays = days;
    this.#save();
    this.store.log(cred, 'reconfirm.settings', null, { days });
  }

  #token(kind, email, userId = null) {
    const token = randomToken(32);
    this.db.prepare('INSERT INTO email_tokens (token_hash,kind,email,user_id,created_at,expires_at) VALUES (?,?,?,?,?,?)')
      .run(sha256hex(token), kind, email, userId, now(), new Date(Date.now() + LINK_TTL).toISOString());
    return token;
  }
  /** Single use: the row is claimed atomically, so two parallel requests can't both spend it. */
  #claim(kind, token) {
    const row = this.db.prepare('SELECT * FROM email_tokens WHERE token_hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?').get(sha256hex(String(token || '')), kind, now());
    return row && this.db.prepare('UPDATE email_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL').run(now(), row.token_hash).changes === 1 ? row : null;
  }
  peek(kind, token) {
    return this.db.prepare('SELECT email FROM email_tokens WHERE token_hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?').get(sha256hex(String(token || '')), kind, now());
  }

  /**
   * Same answer, same work on the request path, for every well-formed address: allowed, not allowed, or
   * already registered. Everything that depends on which (lookup, token, decrypt, send) runs after the
   * response, so neither timing nor an error can tell them apart.
   */
  requestSignup(email) {
    if (!this.signupOpen()) throw httpErr(404, 'Self-signup is not available');
    const e = normEmail(email);
    if (!e) throw httpErr(400, 'Enter a valid email address');
    setImmediate(() => {
      try { this.#signup(e); } catch (err) { console.error(`greenroom: signup mail not sent: ${err.message}`); }
    });
  }
  #signup(e) {
    if (this.throttle(`signup:${e}`, 3, 60 * 60e3)) return this.store.log(null, 'signup.throttled', null, { email: e }); // ponytail: per-address cap can be used to delay a colleague's signup; logged so an admin can see it
    const allowed = this.s.domains.includes(e.split('@')[1]);
    const existing = this.db.prepare('SELECT id FROM users WHERE username = ?').get(e);
    const outcome = !allowed ? 'not_allowed' : existing ? 'existing' : 'link';
    this.store.log(null, 'signup.requested', null, { email: e, outcome });
    if (outcome === 'existing') {
      this.#mail(e, 'You already have a greenroom account', `Someone (hopefully you) asked to sign up at ${this.#origin()} with this address, but it already has an account.\n\nSign in: ${this.#origin()}/login\n\nIf this wasn't you, you can ignore this email.\n`);
    } else if (outcome === 'link') {
      const token = this.#token('signup', e);
      this.#mail(e, 'Confirm your greenroom signup', `Follow this link within 30 minutes to finish creating your account:\n\n${this.#origin()}/signup/${token}\n\nIt works once. If you didn't ask for this, ignore this email.\n`);
    }
  }

  /** Creates a member (never an admin). The domain must still be listed when the link is used. */
  async completeSignup({ token, name, password }) {
    const row = this.#claim('signup', token);
    if (!row || !this.signupOpen() || !this.s.domains.includes(row.email.split('@')[1])) throw httpErr(400, 'This link is invalid or has expired');
    let u;
    try { u = await this.auth.createUser({ email: row.email, password, role: 'member', name }); }
    catch (e) {
      if (e.status === 400) this.db.prepare('UPDATE email_tokens SET used_at = NULL WHERE token_hash = ?').run(row.token_hash); // e.g. short password: let them retry
      throw e;
    }
    this.db.prepare('UPDATE users SET email_confirmed_at = ? WHERE id = ?').run(now(), u.id);
    this.store.log(null, 'signup.completed', null, { email: row.email, user: u.id });
    return u;
  }

  /** Called after a correct password on a lapsed account. At most one fresh link per 5 minutes. */
  sendReconfirm(u) {
    const recent = this.db.prepare("SELECT 1 FROM email_tokens WHERE kind = 'reconfirm' AND user_id = ? AND used_at IS NULL AND created_at > ?")
      .get(u.id, new Date(Date.now() - 5 * 60e3).toISOString());
    if (recent || !this.auth.reconfirm) return;
    const token = this.#token('reconfirm', u.username, u.id);
    this.#mail(u.username, 'Confirm your email for greenroom', `Your greenroom account at ${this.#origin()} needs you to confirm this address every ${this.s.reconfirmDays} days.\n\nConfirm within 30 minutes:\n\n${this.#origin()}/confirm/${token}\n\nThen sign in again.\n`);
  }
  confirm(token) {
    const row = this.#claim('reconfirm', token);
    if (!row) throw httpErr(400, 'This link is invalid or has expired');
    this.db.prepare('UPDATE users SET email_confirmed_at = ? WHERE id = ?').run(now(), row.user_id);
    this.store.log(null, 'user.reconfirmed', null, { user: row.user_id });
  }
}

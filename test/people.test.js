// M6: people. SMTP client, self-signup, offboarding, email re-confirmation (issue #214 section 6).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { boot, client, setupAdmin } from './helpers.js';
import { sendMail, dotStuff } from '../src/mail.js';
import { normEmail, normDomain } from '../src/util.js';

/** A tiny SMTP server: records each message; next() resolves with the next one, or null after `ms`. */
async function fakeSmtp({ greet = true } = {}) {
  const inbox = [], waiting = [];
  const srv = net.createServer((s) => {
    if (greet) s.write('220 fake ESMTP\r\n');
    let buf = '', cur = { cmds: [], lines: [] }, data = false;
    s.on('data', (d) => {
      buf += d;
      for (let i; (i = buf.indexOf('\r\n')) >= 0;) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        if (data) {
          if (line !== '.') { cur.lines.push(line); continue; }
          data = false;
          const m = { ...cur, text: cur.lines.map((l) => (l.startsWith('.') ? l.slice(1) : l)).join('\n') };
          waiting.length ? waiting.shift()(m) : inbox.push(m);
          cur = { cmds: [], lines: [] };
          s.write('250 queued\r\n');
          continue;
        }
        cur.cmds.push(line);
        const v = line.slice(0, 4).toUpperCase();
        s.write(v === 'EHLO' ? '250-fake\r\n250 AUTH PLAIN\r\n' : v === 'AUTH' ? '235 ok\r\n' : v === 'DATA' ? '354 go\r\n' : v === 'QUIT' ? '221 bye\r\n' : '250 ok\r\n');
        if (v === 'DATA') data = true;
      }
    });
    s.on('error', () => {});
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const next = (ms = 2000) => (inbox.length ? Promise.resolve(inbox.shift()) : new Promise((r) => {
    const w = (m) => { clearTimeout(to); r(m); };
    const to = setTimeout(() => { waiting.splice(waiting.indexOf(w), 1); r(null); }, ms);
    waiting.push(w);
  }));
  return { port: srv.address().port, next, close: () => srv.close() };
}
const smtpFor = (port, extra = {}) => ({ host: '127.0.0.1', port, security: 'none', from: 'noreply@example.com', ...extra });
const linkIn = (m, kind) => new RegExp(`/${kind}/([\\w-]+)`).exec(m.text)[1];

async function world() {
  const mail = await fakeSmtp();
  const t = await boot();
  const ada = await setupAdmin(t);
  const done = () => { t.close(); mail.close(); };
  return { t, ada, mail, done };
}
async function invite(t, ada, email, role = 'member') {
  const inv = (await (await ada.post('/api/invites', { role })).json()).invite;
  const c = client(t.base);
  assert.equal((await c.json('/api/invites/accept', { token: inv.split('/').pop(), name: email, email, password: 'correct horse battery' })).status, 201);
  const row = t.db.prepare('SELECT u.id, s.csrf_token FROM users u JOIN sessions s ON s.user_id = u.id WHERE u.username = ?').get(email);
  return Object.assign(c, { id: row.id, csrf: row.csrf_token });
}

test('SMTP client: plain dialogue, AUTH PLAIN, CRLF and dot-stuffing', async () => {
  const mail = await fakeSmtp();
  try {
    await sendMail(smtpFor(mail.port, { user: 'u', pass: 'päss' }), { to: 'bob@example.com', subject: 'Hi é', text: 'one\n.two\n..three\r\nlast' });
    const m = await mail.next();
    assert.equal(m.cmds[0], 'EHLO freespace');
    assert.equal(Buffer.from(m.cmds[1].split(' ')[2], 'base64').toString(), '\0u\0päss');
    assert.deepEqual(m.cmds.slice(2, 5), ['MAIL FROM:<noreply@example.com>', 'RCPT TO:<bob@example.com>', 'DATA']);
    assert.ok(m.lines.includes('..two') && m.lines.includes('...three'), 'leading dots doubled on the wire');
    assert.match(m.text, /\n\none\n\.two\n\.\.three\nlast$/);
    assert.match(m.text, /^Subject: =\?UTF-8\?B\?/m);
    assert.equal(dotStuff('a\r.b\n'), 'a\r\n..b\r\n\r\n.\r\n');
  } finally { mail.close(); }
});

test('SMTP client: header injection and cleartext to a remote host are refused; every step times out', async () => {
  const mail = await fakeSmtp(), mute = await fakeSmtp({ greet: false });
  try {
    for (const bad of [{ subject: 'x\r\nBcc: eve@evil.example' }, { to: 'a@b.com\nBcc: eve@evil.example' }])
      await assert.rejects(sendMail(smtpFor(mail.port), { to: 'a@b.com', subject: 's', text: 't', ...bad }), /line breaks/);
    await assert.rejects(sendMail(smtpFor(mail.port, { from: 'a@b.com\r\nX: y' }), { to: 'a@b.com', subject: 's', text: 't' }), /line breaks/);
    await assert.rejects(sendMail(smtpFor(25, { host: 'mail.example.com' }), { to: 'a@b.com', subject: 's', text: 't' }), /only allowed to a relay on this machine/);
    await assert.rejects(sendMail(smtpFor(mute.port), { to: 'a@b.com', subject: 's', text: 't' }, 200), /SMTP timeout/);
    assert.equal(await mail.next(100), null, 'nothing was sent');
  } finally { mail.close(); mute.close(); }
});

test('SMTP settings: admin only, password stored sealed and never echoed, header values checked', async () => {
  const { t, ada, mail, done } = await world();
  try {
    const bob = await invite(t, ada, 'bob@example.com');
    assert.equal((await bob.json('/api/admin/smtp', smtpFor(mail.port), 'POST', { 'x-csrf-token': bob.csrf })).status, 403);
    assert.equal((await ada.post('/api/admin/smtp', { ...smtpFor(mail.port), from: 'a@b.com\r\nBcc: x@y.com' })).status, 400);
    assert.equal((await ada.post('/api/admin/smtp', { ...smtpFor(mail.port), host: 'mail.example.com' })).status, 400, 'cleartext only to loopback');
    const r = await ada.post('/api/admin/smtp', { ...smtpFor(mail.port), user: 'u', pass: 'hunter2-secret' });
    assert.equal(r.status, 200);
    assert.doesNotMatch(await r.text(), /hunter2/);
    const stored = t.db.prepare("SELECT value FROM meta WHERE key = 'people'").get().value;
    assert.doesNotMatch(stored, /hunter2/);
    assert.doesNotMatch(await (await ada.fetch('/instance')).text(), /hunter2/);
    assert.doesNotMatch(t.db.prepare('SELECT group_concat(detail_json) d FROM activity_log').get().d ?? '', /hunter2/);
    // Saving again with a blank password keeps the stored one; the test email authenticates with it.
    assert.equal((await ada.post('/api/admin/smtp', { ...smtpFor(mail.port), user: 'u', pass: '' })).status, 200);
    assert.equal((await ada.post('/api/admin/smtp/test', {})).status, 200);
    const m = await mail.next();
    assert.equal(Buffer.from(m.cmds[1].split(' ')[2], 'base64').toString(), '\0u\0hunter2-secret');
    assert.deepEqual(m.cmds[3], 'RCPT TO:<ada@example.com>');
  } finally { done(); }
});

test('address and domain normalisation', () => {
  assert.equal(normEmail('Bob@ACME.com'), 'bob@acme.com');
  assert.equal(normEmail('bob@acme.com.'), 'bob@acme.com', 'one trailing dot');
  assert.equal(normEmail('bob@Éxample.org'), 'bob@xn--xample-9ua.org', 'IDN to punycode');
  for (const bad of ['"b o b"@acme.com', 'a@b@acme.com', 'a..b@acme.com', '.a@acme.com', 'a@[127.0.0.1]', 'a@127.0.0.1', 'a@localhost', 'a@acme.com..', 'a b@acme.com', 'a@-acme.com'])
    assert.equal(normEmail(bad), null, bad);
  assert.equal(normDomain('Sub.Acme.COM.'), 'sub.acme.com');
});

test('self-signup: needs SMTP, never enumerates, single-use links that expire, members only', async () => {
  const { t, ada, mail, done } = await world();
  try {
    const anon = client(t.base);
    assert.equal((await anon.json('/api/signup', { email: 'x@acme.com' })).status, 404, 'off by default');
    assert.equal((await ada.post('/api/admin/signup', { enabled: '1', domains: 'acme.com' })).status, 400, 'needs SMTP first');
    assert.equal((await ada.post('/api/admin/smtp', smtpFor(mail.port))).status, 200);
    assert.equal((await ada.post('/api/admin/signup', { enabled: '1', domains: 'ACME.com\nexample.com, Éxample.org' })).status, 200);
    assert.equal((await ada.post('/api/admin/signup', { enabled: '1', domains: 'not a domain' })).status, 400);

    // Allowed, not allowed, already registered: identical status and body, as JSON and as a form.
    const ask = async (email) => { const r = await client(t.base).json('/api/signup', { email }); return [r.status, await r.text()]; };
    const answers = [await ask('new@acme.com'), await ask('who@other.com'), await ask('ada@example.com'), await ask('x@sub.acme.com')];
    for (const a of answers) assert.deepEqual(a, answers[0]);
    const formAsk = async (email) => (await anon.fetch('/api/signup', { method: 'POST', body: new URLSearchParams({ email }), headers: { 'content-type': 'application/x-www-form-urlencoded' } })).headers.get('location');
    assert.equal(await formAsk('who2@other.com'), await formAsk('ada@example.com'));
    assert.equal(answers[0][0], 202);
    const got = [await mail.next(), await mail.next(), await mail.next()].filter(Boolean).sort((a, b) => a.cmds[2].localeCompare(b.cmds[2]));
    assert.equal(await mail.next(300), null, 'not-allowed addresses (including an unlisted subdomain) get nothing');
    assert.deepEqual(got.map((m) => m.cmds[2]), ['RCPT TO:<ada@example.com>', 'RCPT TO:<ada@example.com>', 'RCPT TO:<new@acme.com>']);
    assert.match(got[0].text, /already has an account/);
    const token = linkIn(got[2], 'signup');
    assert.equal(t.db.prepare('SELECT COUNT(*) c FROM email_tokens WHERE token_hash = ?').get(token).c, 0, 'stored hashed');
    assert.equal((await anon.json('/api/signup', { email: 'two@@acme.com' })).status, 400);

    // The link page, then completion. A weak password doesn't burn the link.
    assert.equal((await anon.fetch(`/signup/${token}`)).status, 200);
    assert.equal((await anon.json('/api/signup/complete', { token, name: 'New', password: 'short' })).status, 400);
    assert.equal((await anon.json('/api/signup/complete', { token, name: 'New', password: 'correct horse battery', role: 'admin' })).status, 201);
    assert.equal(t.db.prepare("SELECT role FROM users WHERE username = 'new@acme.com'").get().role, 'member');
    assert.equal((await anon.fetch('/api/me')).status, 200, 'signed in');
    assert.equal((await client(t.base).json('/api/signup/complete', { token, name: 'Again', password: 'correct horse battery' })).status, 400, 'single use');

    // Case, trailing dot and IDN match the listed domain; an expired link is refused.
    await ask('Other@ACME.COM.');
    await ask('u@éxample.org');
    const two = [await mail.next(), await mail.next()].sort((a, b) => a.cmds[2].localeCompare(b.cmds[2]));
    assert.deepEqual(two.map((m) => m.cmds[2]), ['RCPT TO:<other@acme.com>', 'RCPT TO:<u@xn--xample-9ua.org>']);
    assert.equal((await ask('eleven@acme.com'))[0], 429, 'per-IP limit: 10 requests an hour, counted from the first');

    assert.equal((await ada.post('/api/admin/signup', { enabled: '1', domains: 'example.com\nxn--xample-9ua.org' })).status, 200);
    assert.equal((await client(t.base).json('/api/signup/complete', { token: linkIn(two[0], 'signup'), name: 'O', password: 'correct horse battery' })).status, 400, 'domain removed since the link was sent');
    assert.ok(t.db.prepare("SELECT 1 FROM users WHERE username = 'new@acme.com' AND disabled_at IS NULL").get(), 'removing a domain deactivates nobody');
    t.db.prepare("UPDATE email_tokens SET expires_at = '2000-01-01T00:00:00.000Z' WHERE used_at IS NULL").run();
    assert.equal((await client(t.base).json('/api/signup/complete', { token: linkIn(two[1], 'signup'), name: 'Late', password: 'correct horse battery' })).status, 400, 'expired');

    // Cross-site posts are refused like the login form.
    assert.equal((await client(t.base).json('/api/signup', { email: 'q@example.com' }, 'POST', { 'sec-fetch-site': 'cross-site' })).status, 403);
    const acts = t.db.prepare("SELECT action FROM activity_log WHERE action LIKE 'signup.%'").all().map((r) => r.action);
    assert.ok(acts.includes('signup.requested') && acts.includes('signup.completed'));
  } finally { done(); }
});

test('offboarding: deactivation stops session and API key at once; last-admin guard; reactivation revives no session', async () => {
  const { t, ada, done } = await world();
  try {
    assert.equal((await ada.post(`/api/users/${t.db.prepare('SELECT id FROM users').get().id}/deactivate`, {})).status, 400, 'last active admin');
    const bob = await invite(t, ada, 'bob@example.com');
    const minted = await bob.fetch('/api/tokens', { method: 'POST', body: new URLSearchParams({ _csrf: bob.csrf, name: 'k', perms: 'read' }), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    const key = /value="(fsa_[^"]+)"/.exec(await minted.text())[1];
    const asKey = () => fetch(t.base + '/api/me', { headers: { authorization: `Bearer ${key}` } });
    assert.equal((await asKey()).status, 200);
    assert.equal((await ada.post(`/api/users/${bob.id}/deactivate`, {})).status, 200);
    assert.equal((await bob.fetch('/api/me')).status, 401);
    assert.equal((await asKey()).status, 401);
    assert.equal((await client(t.base).json('/api/login', { email: 'bob@example.com', password: 'correct horse battery' })).status, 401);
    assert.match(await (await ada.fetch('/team')).text(), /\(deactivated\)/);
    assert.equal(t.db.prepare('SELECT COUNT(*) c FROM api_keys WHERE user_id = ?').get(bob.id)?.c ?? 1, 1, 'nothing deleted');

    assert.equal((await ada.post(`/api/users/${bob.id}/reactivate`, {})).status, 200);
    assert.equal((await bob.fetch('/api/me')).status, 401, 'old session stays dead');
    assert.equal((await client(t.base).json('/api/login', { email: 'bob@example.com', password: 'correct horse battery' })).status, 200);

    // With a second admin, an admin may step down; the remaining one can't.
    const cy = await invite(t, ada, 'cy@example.com', 'admin');
    const adaId = t.db.prepare("SELECT id FROM users WHERE username = 'ada@example.com'").get().id;
    assert.equal((await ada.post(`/api/users/${adaId}/deactivate`, {})).status, 200);
    assert.equal((await cy.json(`/api/users/${cy.id}/deactivate`, {}, 'POST', { 'x-csrf-token': cy.csrf })).status, 400);
    assert.equal((await bob.fetch('/api/me')).status, 401);
  } finally { done(); }
});

test('re-confirmation: an overdue account stops working until the emailed link is used', async () => {
  const { t, ada, mail, done } = await world();
  try {
    assert.equal((await ada.post('/api/admin/reconfirm', { days: 30 })).status, 400, 'needs SMTP');
    assert.equal((await ada.post('/api/admin/smtp', smtpFor(mail.port))).status, 200);
    const bob = await invite(t, ada, 'bob@example.com');
    const minted = await bob.fetch('/api/tokens', { method: 'POST', body: new URLSearchParams({ _csrf: bob.csrf, name: 'k', perms: 'read' }), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    const key = /value="(fsa_[^"]+)"/.exec(await minted.text())[1];
    const asKey = () => fetch(t.base + '/api/me', { headers: { authorization: `Bearer ${key}` } });
    assert.equal((await ada.post('/api/admin/reconfirm', { days: 30 })).status, 200);
    assert.equal((await bob.fetch('/api/me')).status, 200, 'everyone gets the full grace period when it is turned on');

    // Time passes: bob is overdue, ada confirmed recently.
    const old = new Date(Date.now() - 31 * 864e5).toISOString();
    t.auth.reconfirm.since = old;
    t.db.prepare('UPDATE users SET created_at = ?').run(old);
    t.db.prepare("UPDATE users SET email_confirmed_at = ? WHERE username = 'ada@example.com'").run(new Date().toISOString());
    assert.equal((await bob.fetch('/api/me')).status, 401);
    assert.equal((await asKey()).status, 401);
    assert.equal((await ada.fetch('/api/me')).status, 200);
    assert.match(await (await ada.fetch('/team')).text(), /\(lapsed\)/);

    const r = await client(t.base).json('/api/login', { email: 'bob@example.com', password: 'correct horse battery' });
    assert.equal(r.status, 401);
    assert.match((await r.json()).error, /re-confirming/);
    const m = await mail.next();
    assert.equal(m.cmds[2], 'RCPT TO:<bob@example.com>');
    const token = linkIn(m, 'confirm');
    assert.equal((await client(t.base).json('/api/login', { email: 'bob@example.com', password: 'wrong password!!' })).status, 401);
    assert.equal(await mail.next(200), null, 'a wrong password sends nothing');

    const anon = client(t.base);
    assert.match(await (await anon.fetch(`/confirm/${token}`)).text(), /Confirm/, 'GET only shows a button');
    assert.equal((await bob.fetch('/api/me')).status, 401);
    assert.equal((await anon.json('/api/confirm', { token })).status, 200);
    assert.equal((await anon.json('/api/confirm', { token })).status, 400, 'single use');
    assert.equal((await bob.fetch('/api/me')).status, 200);
    assert.equal((await asKey()).status, 200);
    assert.equal((await client(t.base).json('/api/login', { email: 'bob@example.com', password: 'correct horse battery' })).status, 200);
  } finally { done(); }
});

test('review fixes: dead inviters, legacy usernames, SMTP re-entry, reconfirm clock, lapsed admins, signed-in forms', async () => {
  const { t, ada, mail, done } = await world();
  try {
    // An invite from an admin who is later deactivated can't be accepted.
    const bob = await invite(t, ada, 'bob@example.com', 'admin');
    const inv = (await (await bob.json('/api/invites', { role: 'admin' }, 'POST', { 'x-csrf-token': bob.csrf })).json()).invite;
    assert.equal((await ada.post(`/api/users/${bob.id}/deactivate`, {})).status, 200);
    assert.equal((await client(t.base).json('/api/invites/accept', { token: inv.split('/').pop(), name: 'Eve', email: 'eve@evil.example', password: 'correct horse battery' })).status, 400);
    assert.equal(t.db.prepare("SELECT 1 FROM users WHERE username = 'eve@evil.example'").get(), undefined);
    assert.equal((await ada.post(`/api/users/${bob.id}/reactivate`, {})).status, 200);
    assert.equal((await client(t.base).json('/api/invites/accept', { token: inv.split('/').pop(), name: 'Eve', email: 'eve@evil.example', password: 'correct horse battery' })).status, 400, 'reactivation does not revive it');

    // A row stored before M6 (lowercased, otherwise as typed) still signs in.
    const legacy = t.db.prepare("SELECT password_hash FROM users WHERE username = 'ada@example.com'").get().password_hash;
    for (const u of ['user@münchen.de', 'jürgen@acme.com', 'x@sub_domain.acme.com']) {
      t.db.prepare("INSERT INTO users (id,username,password_hash,role,created_at,updated_at,display_name) VALUES (?,?,?,'member',?,?,'L')").run(`usr_${u.length}${u[0]}`, u, legacy, new Date().toISOString(), new Date().toISOString());
      assert.equal((await client(t.base).json('/api/login', { email: ` ${u.toUpperCase()} `, password: 'correct horse battery' })).status, 200, u);
    }

    // The stored SMTP password is only reused for the same server and username.
    assert.equal((await ada.post('/api/admin/smtp', { ...smtpFor(mail.port), user: 'u', pass: 'secret-pass' })).status, 200);
    assert.equal((await ada.post('/api/admin/smtp', { ...smtpFor(mail.port), host: 'localhost', user: 'u' })).status, 400);
    assert.equal((await ada.post('/api/admin/smtp', { ...smtpFor(mail.port + 1), user: 'u' })).status, 400);
    assert.equal((await ada.post('/api/admin/smtp', { ...smtpFor(mail.port), user: 'u', from: 'other@example.com' })).status, 200);

    // Lowering N, or SMTP coming back, restarts everyone's clock instead of lapsing them on the spot.
    assert.equal((await ada.post('/api/admin/reconfirm', { days: 90 })).status, 200);
    const old = new Date(Date.now() - 60 * 864e5).toISOString();
    t.db.prepare('UPDATE users SET created_at = ?').run(old);
    t.people.s.reconfirmSince = t.auth.reconfirm.since = old;
    assert.equal((await ada.post('/api/admin/reconfirm', { days: 30 })).status, 200);
    assert.equal((await ada.fetch('/api/me')).status, 200);
    assert.equal((await ada.post('/api/admin/smtp', { clear: '1' })).status, 200);
    t.people.s.reconfirmSince = old;
    assert.equal((await ada.post('/api/admin/smtp', { ...smtpFor(mail.port) })).status, 200);
    assert.equal((await ada.fetch('/api/me')).status, 200);

    // A lapsed admin doesn't count as the other active admin.
    t.people.s.reconfirmSince = t.auth.reconfirm.since = old;
    t.db.prepare("UPDATE users SET email_confirmed_at = ? WHERE username = 'ada@example.com'").run(new Date().toISOString());
    const adaId = t.db.prepare("SELECT id FROM users WHERE username = 'ada@example.com'").get().id;
    assert.equal((await ada.post(`/api/users/${adaId}/deactivate`, {})).status, 400, 'bob is a lapsed admin');

    // A signed-in person can submit the token forms: they carry the CSRF token.
    assert.equal((await client(t.base).json('/api/login', { email: 'bob@example.com', password: 'correct horse battery' })).status, 401);
    const token = linkIn(await mail.next(), 'confirm');
    const page = await (await ada.fetch(`/confirm/${token}`)).text();
    const csrf = /name="_csrf" value="([^"]+)"/.exec(page)[1];
    const r = await ada.fetch('/api/confirm', { method: 'POST', body: new URLSearchParams({ _csrf: csrf, token }), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    assert.equal(r.status, 303);
    assert.ok(t.db.prepare("SELECT email_confirmed_at FROM users WHERE username = 'bob@example.com'").get().email_confirmed_at);
  } finally { done(); }
});

test('signup: the response is decided before any per-outcome work, and the per-address cap is logged', async () => {
  const { t, ada, mail, done } = await world();
  try {
    assert.equal((await ada.post('/api/admin/smtp', smtpFor(mail.port))).status, 200);
    assert.equal((await ada.post('/api/admin/signup', { enabled: '1', domains: 'acme.com\nexample.com' })).status, 200);
    // A broken secret makes decryption throw; every outcome still gets the same 202.
    t.db.prepare("UPDATE meta SET value = json_set(value, '$.smtp.pass', 'AAAA.AAAA.AAAA') WHERE key = 'people'").run();
    t.people.s.smtp.pass = 'AAAA.AAAA.AAAA';
    for (const e of ['n@acme.com', 'ada@example.com', 'x@other.com']) assert.equal((await client(t.base).json('/api/signup', { email: e })).status, 202, e);
    t.people.s.smtp.pass = null;
    for (let i = 0; i < 4; i++) await client(t.base).json('/api/signup', { email: 'victim@acme.com' });
    await new Promise((r) => setImmediate(r));
    assert.ok(t.db.prepare("SELECT 1 FROM activity_log WHERE action = 'signup.throttled'").get());
  } finally { done(); }
});

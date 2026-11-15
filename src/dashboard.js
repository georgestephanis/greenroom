// Server-rendered dashboard: HTML plus a few lines of vanilla JS. No build step.
import { esc } from './util.js';

// Rule 8: the preview iframe is sandboxed by attribute as well as by the response header, and never
// gets allow-same-origin, so the dashboard never renders space content same-origin.
export const PREVIEW_SANDBOX = 'allow-scripts allow-forms allow-popups allow-modals allow-downloads';

const fmtBytes = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);
// Stored times are UTC ISO; the UTC text is the no-JS fallback and app.js shows the viewer's local time.
export const fmtTime = (t) => (t ? `<time datetime="${esc(t)}">${esc(t.slice(0, 16).replace('T', ' '))} UTC</time>` : '');

export function layout(title, cred, body, { nav = true, head = '' } = {}) {
  const csrf = cred?.csrf ? `<meta name="csrf" content="${esc(cred.csrf)}">` : '';
  const admin = cred?.user?.role === 'admin';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · greenroom</title>${csrf}<link rel="stylesheet" href="/assets/app.css"><script src="/assets/app.js" defer></script>${head}</head>
<body>${nav && cred ? `<header><a class="brand" href="/">greenroom</a><nav><a href="/">Spaces</a><a href="/access">Access</a>${admin ? '<a href="/team">Team</a><a href="/instance">Instance</a>' : ''}<a href="/account">${esc(cred.user.display_name || cred.user.username)}</a>
<form method="post" action="/api/logout" class="inline">${hidden(cred)}<input type="hidden" name="_next" value="/login"><button class="link">Sign out</button></form></nav></header>` : ''}
<main>${body}</main></body></html>`;
}
const hidden = (cred) => (cred?.csrf ? `<input type="hidden" name="_csrf" value="${esc(cred.csrf)}">` : '');

export function authPage(title, cred, error, fields, action, button, extra = '') {
  return layout(title, cred, `<section class="card narrow"><h1>${esc(title)}</h1>${error ? `<p class="error">${esc(error)}</p>` : ''}
<form method="post" action="${action}">${hidden(cred)}${extra}${fields}<button>${esc(button)}</button></form></section>`, { nav: false });
}
const field = (name, label, type = 'text', attrs = '') => `<label>${esc(label)}<input name="${name}" type="${type}" ${attrs} required></label>`;
export const loginFields = field('email', 'Email', 'email', 'autocomplete="username"') + field('password', 'Password', 'password', 'autocomplete="current-password"');
export const setupFields = field('name', 'Your name', 'text', 'autocomplete="name"') + field('email', 'Email', 'email', 'autocomplete="username"') + field('password', 'Password (10+ characters)', 'password', 'minlength="10" autocomplete="new-password"');

export function spacesPage(cred, spaces) {
  const rows = spaces.map((s) => `<tr><td><a href="/spaces/${esc(s.slug)}">${esc(s.name)}</a><br><small>/s/${esc(s.slug)}/</small></td>
<td><span class="badge ${esc(s.privacy)}">${s.privacy === 'team' ? 'Team only' : s.privacy === 'public' ? 'Public' : 'Anyone with the link'}</span></td>
<td>${s.live_number ? `v${s.live_number} by ${esc(s.live_author)}<br><small>${fmtTime(s.live_at)}</small>` : '<small>nothing published</small>'}</td></tr>`).join('');
  return layout('Spaces', cred, `<h1>Spaces</h1>
<table><thead><tr><th>Space</th><th>Who can view</th><th>Last published</th></tr></thead><tbody>${rows || '<tr><td colspan="3">No spaces yet.</td></tr>'}</tbody></table>
<section class="card"><h2>New space</h2><form method="post" action="/api/spaces">${hidden(cred)}<input type="hidden" name="_next" value="__space__">${field('name', 'Name')}<button>Create</button></form></section>
<section class="card"><h2>Import a space</h2><form data-upload="/api/import" data-goto="space"><input type="file" name="zip" accept=".zip,application/zip" required>
<input name="slug" placeholder="Slug (optional; defaults to the one in the bundle)"><label class="check"><input type="checkbox" name="replace" value="1"> Replace the space if that slug exists (its versions are replaced; links and activity stay)</label>
<button>Import</button><span class="status"></span></form><small>Takes a .greenroom.zip or .greenroom-history.zip exported from greenroom.</small></section>`);
}

export function spacePage(cred, space, versions, warnings, links, plugins = []) {
  const live = versions.find((v) => v.id === space.live_version_id);
  const hist = versions.map((v, i) => {
    const prev = versions[i + 1];
    return `<li><strong>v${v.number}</strong> ${v.id === space.live_version_id ? '<span class="badge live">live</span>' : ''}
${esc(v.message || '(no message)')}<br><small>${esc(v.author_name)} · ${esc(v.source)} · ${v.total_files} files · ${fmtBytes(v.total_bytes)} · ${fmtTime(v.created_at)}</small><br>
${prev ? `<a href="/spaces/${esc(space.slug)}/diff?from=${prev.number}&to=${v.number}">Diff vs v${prev.number}</a>` : ''}
${v.id !== space.live_version_id ? `<form method="post" action="/api/spaces/${esc(space.slug)}/rollback" class="inline">${hidden(cred)}<input type="hidden" name="version" value="${v.number}"><input type="hidden" name="_next" value="/spaces/${esc(space.slug)}"><button class="link">Restore</button></form>` : ''}</li>`;
  }).join('');
  return layout(space.name, cred, `<h1>${esc(space.name)}</h1><p><a href="/s/${esc(space.slug)}/" target="_blank" rel="noopener">/s/${esc(space.slug)}/</a></p>
${live ? `<iframe class="preview" sandbox="${PREVIEW_SANDBOX}" src="/s/${esc(space.slug)}/" title="Preview of ${esc(space.name)}"></iframe>` : '<p>Nothing published yet. Upload a zip below.</p>'}
${warnings.length ? `<section class="card warn"><h2>Warnings on the live version</h2><ul>${warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul></section>` : ''}
<section class="card"><h2>Upload</h2><form data-upload="/api/spaces/${esc(space.slug)}/upload"><input type="file" name="zip" accept=".zip,application/zip" required>
<input name="message" placeholder="What changed?"><button>Publish zip</button><span class="status"></span></form></section>
<section class="card"><h2>Export</h2><p><a href="/spaces/${esc(space.slug)}/export">Download current site</a> · <a href="/spaces/${esc(space.slug)}/export?history=1">Download with full history</a></p>
<small>Share links and passwords are never included.</small></section>
<section class="card"><h2>Who can view</h2><form method="post" action="/api/spaces/${esc(space.slug)}">${hidden(cred)}<input type="hidden" name="_method" value="PATCH"><input type="hidden" name="_next" value="/spaces/${esc(space.slug)}">
<select name="privacy">${[['team', 'Team only'], ['link', 'Anyone with the link'], ['public', 'Public']].map(([v, l]) => `<option value="${v}"${space.privacy === v ? ' selected' : ''}>${l}</option>`).join('')}</select>
<button>Save</button></form><small>Team members can always view. Switching away from “Anyone with the link” pauses its links; switching back restores them. A link created while the space is team-only switches it to “Anyone with the link”; links paused earlier stay paused until you resume them.</small></section>
${links ? sharing(cred, space, links) : ''}
${pluginsCard(cred, space, plugins)}
<section class="card"><h2>History</h2><ol class="history">${hist || '<li>No versions.</li>'}</ol></section>`);
}

export function diffPage(cred, space, d, texts) {
  const list = (title, items, f) => (items.length ? `<h3>${title}</h3><ul>${items.map(f).join('')}</ul>` : '');
  const td = texts.map(({ path, ops }) => `<h4>${esc(path)}</h4>${ops ? `<pre class="diff">${ops.filter(([o]) => o !== ' ').map(([o, l]) => `<span class="${o === '+' ? 'add' : 'del'}">${o} ${esc(l)}</span>`).join('\n')}</pre>` : '<p><small>Too large or not text.</small></p>'}`).join('');
  return layout(`Diff ${space.name}`, cred, `<h1>${esc(space.name)}: v${d.from} → v${d.to}</h1><p><a href="/spaces/${esc(space.slug)}">Back</a></p>
${list('Added', d.added, (f) => `<li>${esc(f.path)} <small>${fmtBytes(f.size)}</small></li>`)}${list('Removed', d.removed, (f) => `<li>${esc(f.path)}</li>`)}${list('Changed', d.changed, (f) => `<li>${esc(f.path)} <small>${fmtBytes(f.from)} → ${fmtBytes(f.to)}</small></li>`)}
${!d.added.length && !d.removed.length && !d.changed.length ? '<p>No differences.</p>' : ''}${td}`);
}

export const signupFields = field('name', 'Your name', 'text', 'autocomplete="name"') + field('password', 'Password (10+ characters)', 'password', 'minlength="10" autocomplete="new-password"');
// One page for every outcome: allowed, not allowed and already registered all read "check your inbox".
export const signupPage = (cred, sent, error) => (sent
  ? messagePage(null, 'Check your inbox', 'If that address can sign up here, we have sent it a link. It is valid for 30 minutes.')
  : authPage('Sign up', cred, error, field('email', 'Work email', 'email', 'autocomplete="email"'), '/api/signup', 'Send me a link'));

// ponytail: name and password only. Email is the sign-in and the signup allowlist's subject, so changing it
// needs a confirmation round trip; add it with people.js's mail flow when someone asks.
export function accountPage(cred, saved, error) {
  const u = cred.user;
  return layout('Account', cred, `<h1>Account</h1>${error ? `<p class="error">${esc(error)}</p>` : ''}
${saved === 'name' ? '<p class="ok">Name saved.</p>' : saved === 'password' ? '<p class="ok">Password changed. Your other sessions are signed out.</p>' : ''}
<section class="card"><h2>Profile</h2><form method="post" action="/api/account">${hidden(cred)}
<label>Name<input name="name" value="${esc(u.display_name || '')}" maxlength="100" autocomplete="name" required></label>
<p><small>Signed in as ${esc(u.username)} (${esc(u.role)}). Changing your email isn't supported yet.</small></p><button>Save</button></form></section>
<section class="card"><h2>Password</h2><form method="post" action="/api/account/password">${hidden(cred)}
<input type="hidden" name="username" value="${esc(u.username)}" autocomplete="username">
${field('current', 'Current password', 'password', 'autocomplete="current-password"')}${field('password', 'New password (10+ characters)', 'password', 'minlength="10" autocomplete="new-password"')}
<button>Change password</button></form></section>`);
}

export function teamPage(cred, users, invites, created) {
  return layout('Team', cred, `<h1>Team</h1>
${created ? `<section class="card ok"><p>Invite link (shown once, valid 7 days):</p><input readonly class="wide" value="${esc(created)}"></section>` : ''}
<table><thead><tr><th>Person</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead><tbody>${users.map((u) => `<tr><td>${esc(u.display_name)}<br><small>${esc(u.username)}</small></td><td>${esc(u.role)}${u.disabled_at ? ' <strong>(deactivated)</strong>' : u.lapsed ? ' <strong>(lapsed)</strong>' : ''}</td><td>${fmtTime(u.last_login_at)}</td>
<td><form method="post" action="/api/users/${esc(u.id)}/${u.disabled_at ? 'reactivate' : 'deactivate'}" class="inline">${hidden(cred)}<button class="link">${u.disabled_at ? 'Reactivate' : 'Deactivate'}</button></form></td></tr>`).join('')}</tbody></table>
<section class="card"><h2>Invite someone</h2><form method="post" action="/api/invites">${hidden(cred)}<input type="hidden" name="_next" value="__invite__">
<label>Role<select name="role"><option value="member">Member</option><option value="admin">Admin</option></select></label><button>Create invite link</button></form>
<small>${invites} unused invite(s) outstanding.</small></section>`);
}

function sharing(cred, space, links) {
  const status = (l) => (l.revoked_at ? 'revoked' : l.disabled_at ? 'paused' : l.active ? 'active' : 'expired');
  const rows = links.map((l) => `<tr><td>${esc(l.label)}${l.password ? ' <span class="badge">password</span>' : ''}<br><small><code>…${esc(l.hint)}</code></small></td>
<td>${status(l)}<br><small>${l.expires_at ? `until ${fmtTime(l.expires_at)}` : 'no expiry'}</small></td><td>${l.uses}${l.max_uses != null ? ` / ${l.max_uses}` : ''}</td>
<td>${l.view_count}<br><small>${l.last_viewed_at ? `last ${fmtTime(l.last_viewed_at)}` : 'not opened yet'}</small></td>
<td>${l.disabled_at && !l.revoked_at && space.privacy === 'link' ? `<form method="post" action="/api/spaces/${esc(space.slug)}/links/${esc(l.id)}/resume" class="inline">${hidden(cred)}<button class="link">Resume</button></form> ` : ''}${l.revoked_at ? '' : `<form method="post" action="/api/spaces/${esc(space.slug)}/links/${esc(l.id)}/revoke" class="inline">${hidden(cred)}<button class="link">Revoke</button></form>`}</td></tr>`).join('');
  return `<section class="card" id="sharing"><h2>Sharing</h2>
${links.length ? `<table><thead><tr><th>Link</th><th>Status</th><th>Uses</th><th>Views</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : '<p>No share links yet. Creating one switches a team-only space to “Anyone with the link”.</p>'}
<form method="post" action="/api/spaces/${esc(space.slug)}/links">${hidden(cred)}<h3>New link</h3>
<label>Label <input name="label" placeholder="Acme — CFO" maxlength="200"></label>
<label>Expires <select name="expires_in" data-expiry><option value="">Never</option><option value="1d">In 1 day</option><option value="7d">In 1 week</option><option value="30d">In 30 days</option><option value="" data-custom hidden>Custom…</option></select></label>
<label hidden>Expires at (your local time) <input type="datetime-local" data-expiry-local><input type="hidden" name="expires_at"></label>
<label>Password <input type="password" name="password" autocomplete="new-password"></label>
<label>Max uses <input type="number" name="max_uses" min="1" step="1"></label>
<button>Create link</button></form><small>A use is spent each time a new browser opens the link. Views count page loads.</small></section>`;
}

export function instancePage(cred, stats, gc, dcr, brand, plugins = [], ppl = {}) {
  const m = ppl.smtp || {}, sel = (v) => (m.security === v ? ' selected' : '');
  return layout('Instance', cred, `<h1>Instance</h1><ul><li>${stats.spaces} spaces, ${stats.versions} versions, ${stats.users} people</li><li>${fmtBytes(stats.bytesReferenced)} referenced in blob storage</li></ul>
${gc ? `<p class="ok">GC removed ${gc.removed} file(s), freed ${fmtBytes(gc.freed)}.</p>` : ''}
<form method="post" action="/api/admin/gc">${hidden(cred)}<input type="hidden" name="_next" value="/instance?gc=1"><button>Run GC</button></form>
<p><small>Garbage collection also runs lazily after publishes and deletes (at most every few hours). There are no background timers.</small></p>
<section class="card"><h2>Dynamic client registration</h2><p>${dcr ? 'On' : 'Off'}. Clients normally identify themselves with a metadata URL; turn this on only for clients that need RFC 7591 registration.</p>
<form method="post" action="/api/admin/dcr">${hidden(cred)}<input type="hidden" name="_next" value="/instance"><input type="hidden" name="enabled" value="${dcr ? '0' : '1'}"><button>${dcr ? 'Turn off' : 'Turn on'}</button></form></section>
<section class="card" id="people"><h2>Email (SMTP)</h2>${ppl.mailed ? '<p class="ok">Test email sent.</p>' : ''}<p>Needed for self-signup and re-confirmation. ${ppl.smtp ? 'Configured.' : 'Not configured.'}</p>
<form method="post" action="/api/admin/smtp">${hidden(cred)}<label>Host <input name="host" value="${esc(m.host)}" required></label><label>Port <input type="number" name="port" value="${esc(m.port || 465)}" min="1" max="65535" required></label>
<label>Security <select name="security"><option value="tls"${sel('tls')}>Implicit TLS (465)</option><option value="starttls"${sel('starttls')}>STARTTLS (587)</option><option value="none"${sel('none')}>None (relay on this machine only)</option></select></label>
<label>Username <input name="user" value="${esc(m.user)}" autocomplete="off"></label><label>Password <input type="password" name="pass" autocomplete="new-password" placeholder="${m.hasPass ? 'Saved; leave blank to keep' : ''}"></label>
<label>From address <input type="email" name="from" value="${esc(m.from)}" required></label><button>Save SMTP</button></form>
${ppl.smtp ? `<form method="post" action="/api/admin/smtp/test" class="inline">${hidden(cred)}<button>Send test email to me</button></form> <form method="post" action="/api/admin/smtp" class="inline">${hidden(cred)}<input type="hidden" name="clear" value="1"><button class="link">Remove SMTP settings</button></form>` : ''}</section>
<section class="card"><h2>Self-signup</h2><p>${ppl.signupOpen ? 'On: <a href="/signup">/signup</a>' : 'Off'}. People with an address at a listed domain can create a <em>member</em> account. Subdomains must be listed separately. Removing a domain does not deactivate anyone.</p>
<form method="post" action="/api/admin/signup">${hidden(cred)}<label>Domains (one per line) <textarea name="domains" rows="3">${esc((ppl.domains || []).join('\n'))}</textarea></label>
<label>Enabled <select name="enabled"><option value="1"${ppl.signup ? ' selected' : ''}>On</option><option value="0"${ppl.signup ? '' : ' selected'}>Off</option></select></label><button>Save</button></form></section>
<section class="card"><h2>Email re-confirmation</h2><p>Every N days each person must confirm their address by email; until they do, their sessions, tokens and app connections stop working. 0 turns it off.</p>
<form method="post" action="/api/admin/reconfirm">${hidden(cred)}<label>Days <input type="number" name="days" min="0" max="3650" value="${esc(ppl.reconfirmDays || 0)}"></label><button>Save</button></form></section>
<section class="card"><h2>Branding</h2><p>Shown to clients on the password, not-found and expired-link pages.</p>
<form method="post" action="/api/admin/branding">${hidden(cred)}<label>Agency name <input name="name" value="${esc(brand.name)}" maxlength="100"></label>
<label>Logo URL <input type="url" name="logo" value="${esc(brand.logo)}" placeholder="https://…"></label>
<label>Accent colour <input type="color" name="accent" value="${esc(brand.accent || '#1a73e8')}"></label><button>Save branding</button></form></section>
<section class="card"><h2>Move to Spacefast</h2><p>Done self-hosting? Copy your spaces, with their history if you like, to Spacefast or a homefast instance. Nothing here changes.</p><p><a href="/instance/migrate">Move spaces…</a></p></section>
<section class="card"><h2>Plugins</h2><p>Installed plugins are off until you turn them on here; each space then opts in on its own page.</p><ul>${plugins.map((p) => `<li><strong>${esc(p.name)}</strong> ${esc(p.version)} \u2014 ${esc(p.description)}
<form method="post" action="/api/admin/plugins/${esc(p.name)}" class="inline">${hidden(cred)}<input type="hidden" name="_next" value="/instance"><input type="hidden" name="enabled" value="${p.on ? '0' : '1'}"><button class="link">${p.on ? 'Turn off' : 'Turn on'}</button></form></li>`).join('')}</ul></section>`);
}

export function migratePage(cred, spaces, job, error) {
  const running = job && !job.done;
  const rows = job ? `<table><thead><tr><th>Space</th><th>Status</th><th>Versions</th><th>Notes</th></tr></thead><tbody>${job.spaces.map((s) => `<tr><td>${esc(s.name)} <small>${esc(s.slug)}</small></td><td>${esc(s.status)}</td><td>${s.versions}</td><td>${esc(s.note)}${s.url ? ` <a href="${esc(s.url)}" rel="noreferrer">Open</a>` : ''}</td></tr>`).join('')}</tbody></table>` : '';
  const report = job ? `<section class="card"><h2>${running ? 'Moving…' : 'Report'}</h2><p>To ${esc(job.target)}, ${job.history ? 'with history' : 'live versions only'}. Started ${fmtTime(job.startedAt)}${job.finishedAt ? `, finished ${fmtTime(job.finishedAt)}` : ''}.</p>${rows}
${running ? '<p><small>This page refreshes every few seconds. You can leave it; the move keeps going.</small></p>' : `<p>Not carried over: ${job.notCarried.map(esc).join('; ')}. Your spaces still run here until you delete them.</p>`}</section>` : '';
  const form = running ? '' : `<section class="card"><h2>Move spaces</h2><p>Mint an API key on the target that can create spaces and publish (on Spacefast: <em>Settings → API keys</em>), and paste it here. It is used for this move only and never saved.</p>
${error ? `<p class="error">${esc(error)}</p>` : ''}<form method="post" action="/api/admin/migrate">${hidden(cred)}<input type="hidden" name="_next" value="/instance/migrate">
<label>API address <input type="url" name="url" value="https://api.spacefast.com" required></label>
<label>API key <input type="password" name="token" autocomplete="off" required></label>
<fieldset><legend>Spaces</legend>${spaces.map((s) => `<label class="check"><input type="checkbox" name="spaces" value="${esc(s.slug)}" checked> ${esc(s.name)} <small>${esc(s.privacy)}</small></label>`).join('') || '<small>No spaces yet.</small>'}</fieldset>
<label class="check"><input type="checkbox" name="history" value="1"> Include every earlier version (oldest first; only the version live here goes live there)</label>
<p><small>Team and link-only spaces become private; public spaces stay public. A slug already taken on the target is skipped and reported.</small></p><button>Start the move</button></form></section>`;
  return layout('Move to Spacefast', cred, `<h1>Move to Spacefast</h1>${report}${form}`, { head: running ? '<meta http-equiv="refresh" content="3">' : '' });
}

// A generic form per plugin, drawn from its spaceSettings spec. A plugin on the space but not installed
// here keeps its data; this just says so.
function pluginsCard(cred, space, rows) {
  const shown = rows.filter((p) => p.enabled || p.instance_enabled);
  if (!shown.length) return '';
  const input = (p, k, sp) => {
    const v = p.settings[k], n = `s_${k}`;
    if (sp.type === 'enum') return `<select name="${n}">${sp.values.map((o) => `<option${o === v ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
    if (sp.type === 'bool') return `<select name="${n}"><option value="1"${v ? ' selected' : ''}>Yes</option><option value="0"${v ? '' : ' selected'}>No</option></select>`;
    if (sp.type === 'number') return `<input type="number" name="${n}" value="${esc(v)}" min="${sp.min ?? ''}" max="${sp.max ?? ''}">`;
    if (sp.type === 'map') return `<textarea name="${n}" rows="4" placeholder="table: read">${esc(Object.entries(v ?? {}).map(([a, b]) => `${a}: ${b}`).join('\n'))}</textarea>`;
    return `<input name="${n}" value="${esc(v)}" maxlength="${sp.max ?? 200}">`;
  };
  return `<section class="card" id="plugins"><h2>Plugins</h2>${shown.map((p) => !p.installed
    ? `<p class="warn"><strong>${esc(p.name)}</strong> is on for this space but not installed on this instance. Its data is kept; it works again once an admin installs and enables it.</p>`
    : `<form method="post" action="/api/spaces/${esc(space.slug)}/plugins/${esc(p.name)}">${hidden(cred)}<input type="hidden" name="_method" value="PUT"><input type="hidden" name="_next" value="/spaces/${esc(space.slug)}#plugins">
<h3>${esc(p.name)}</h3><small>${esc(p.description)}</small>
<label>Enabled <select name="enabled"><option value="1"${p.enabled ? ' selected' : ''}>On</option><option value="0"${p.enabled ? '' : ' selected'}>Off</option></select></label>
${Object.entries(p.spec).map(([k, sp]) => `<label>${esc(sp.label || k)} ${input(p, k, sp)}</label>`).join('')}<button>Save</button></form>`).join('')}</section>`;
}

export const messagePage = (cred, title, msg) => layout(title, cred, `<section class="card narrow"><h1>${esc(title)}</h1><p>${esc(msg)}</p></section>`, { nav: false });

const PERM_LABELS = { read: 'Read files and history', publish: 'Publish and roll back', db: 'Use space databases', share: 'Manage share links', export: 'Export spaces' };
// Space picker, create toggle and permission picker: shared by OAuth consent and the token minting form.
function scopeFields(spaces, pick = { spaces: [], create: false, perms: ['read'] }) {
  return `<fieldset><legend>Spaces</legend>${spaces.map((s) => `<label class="check"><input type="checkbox" name="spaces" value="${esc(s.slug)}"${pick.spaces.includes(s.slug) ? ' checked' : ''}> ${esc(s.name)} <small>/s/${esc(s.slug)}/</small></label>`).join('') || '<small>No spaces yet.</small>'}
<label class="check"><input type="checkbox" name="create" value="1"${pick.create ? ' checked' : ''}> Can create new spaces (they join this access)</label></fieldset>
<fieldset><legend>Permissions</legend>${Object.entries(PERM_LABELS).map(([k, l]) => `<label class="check"><input type="checkbox" name="perms" value="${k}"${pick.perms.includes(k) ? ' checked' : ''}> ${esc(l)}</label>`).join('')}</fieldset>`;
}

export function consentPage(cred, client, q, requested, spaces) {
  const keep = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'response_type', 'scope']
    .filter((k) => q[k] !== undefined).map((k) => `<input type="hidden" name="${k}" value="${esc(q[k])}">`).join('');
  const pick = requested.perms.length || requested.spaces.length || requested.create ? requested : undefined;
  return layout('Connect an app', cred, `<section class="card narrow"><h1>Connect ${esc(client.client_name)}?</h1>
<p><strong>${esc(client.client_name)}</strong> (<code>${esc(client.client_id)}</code>) wants to act as you, ${esc(cred.user.display_name || cred.user.username)}. It will send you back to <code>${esc(new URL(q.redirect_uri).origin)}</code>.</p>
<p><small>It can never manage people, tokens or settings, or make a space public. You can revoke it any time under Access.</small></p>
<form method="post" action="/oauth/authorize">${hidden(cred)}${keep}${scopeFields(spaces, pick)}
<button name="decision" value="approve">Allow</button> <button name="decision" value="deny" class="link">Deny</button></form></section>`, { nav: false });
}

export function accessPage(cred, rows, spaces, minted) {
  if (minted) return layout('Access', cred, `<h1>New agent token</h1><section class="card ok"><p>Copy it now; it is shown once.</p><input readonly class="wide" value="${esc(minted)}"></section><p><a href="/access">Back to Access</a></p>`);
  const groups = new Map();
  for (const r of rows) {
    const key = r.kind === 'oauth' ? `${r.client_name} — ${r.client_id}` : 'Pasted agent tokens';
    groups.set(key, [...(groups.get(key) || []), r]);
  }
  const admin = cred.user.role === 'admin';
  const list = [...groups].map(([g, rs]) => `<h2>${esc(g)}</h2><table><thead><tr><th>Name</th><th>Scope</th>${admin ? '<th>Granted by</th>' : ''}<th>Last used</th><th></th></tr></thead><tbody>${rs.map((r) => `<tr><td>${esc(r.name)}<br><small>${fmtTime(r.created_at)}</small></td><td><code>${esc(r.scope)}</code></td>${admin ? `<td>${esc(r.granter)}</td>` : ''}<td>${fmtTime(r.last_used_at) || '<small>never</small>'}</td>
<td><form method="post" action="/api/tokens/${esc(r.id)}/revoke" class="inline">${hidden(cred)}<input type="hidden" name="_next" value="/access"><button class="link">Revoke</button></form></td></tr>`).join('')}</tbody></table>`).join('');
  return layout('Access', cred, `<h1>Access</h1><p>Apps and agents that act for ${admin ? 'members of this team' : 'you'}. Revoking ends them immediately.</p>
${list || '<p>Nothing connected yet.</p>'}
<section class="card"><h2>New agent token</h2><p><small>For agents that take a pasted <code>Authorization: Bearer</code> token instead of signing in.</small></p>
<form method="post" action="/api/tokens">${hidden(cred)}<input type="hidden" name="_next" value="/access"><label>Label (shown in history)<input name="name" required></label>${scopeFields(spaces)}<button>Create token</button></form></section>`);
}

export const shownOnce = (cred, { title, value, back }) => layout(title, cred, `<h1>${esc(title)}</h1><section class="card ok"><p>Copy it now; it is shown once.</p><input readonly class="wide" value="${esc(value)}"></section><p><a href="${esc(back)}">Back</a></p>`);

export const notFoundPage = (cred) => layout('Not found', cred, '<h1>Not found</h1><p><a href="/">Back to spaces</a></p>');

export const APP_JS = `
(() => {
  for (const f of document.querySelectorAll('form[data-upload]')) {
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      const file = f.elements.zip.files[0];
      if (!file) return;
      const status = f.querySelector('.status');
      status.textContent = 'Uploading…';
      const p = new URLSearchParams();
      for (const el of f.elements) if (el.name && el.name !== 'zip' && el.value && (el.type !== 'checkbox' || el.checked)) p.set(el.name, el.value);
      const q = p.size ? '?' + p : '';
      const r = await fetch(f.dataset.upload + q, {
        method: 'POST', body: file,
        headers: { 'Content-Type': 'application/zip', 'X-CSRF-Token': document.querySelector('meta[name=csrf]').content },
      });
      if (r.ok && f.dataset.goto) {
        const j = await r.json(), to = '/spaces/' + j.space.slug;
        if (!j.warnings.length) return (location.href = to);
        status.textContent = '';
        const a = document.createElement('a'); a.href = to; a.textContent = 'Open the imported space';
        status.append(j.warnings.join(' '), ' ', a);
      } else if (r.ok) location.reload();
      else status.textContent = (await r.json().catch(() => ({}))).error || 'Upload failed';
    });
  }
  for (const el of document.querySelectorAll('time[datetime]')) {
    const d = new Date(el.dateTime);
    if (isNaN(d)) continue;
    el.title = el.textContent;
    el.textContent = d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }
  // Expiry: the Custom option needs JS, since datetime-local has no timezone; it is sent as UTC ISO.
  for (const sel of document.querySelectorAll('select[data-expiry]')) {
    const f = sel.form, local = f.querySelector('[data-expiry-local]'), out = f.elements.expires_at;
    const custom = () => !!sel.selectedOptions[0].dataset.custom;
    sel.querySelector('[data-custom]').hidden = false;
    sel.addEventListener('change', () => { local.parentElement.hidden = !custom(); local.required = custom(); });
    f.addEventListener('submit', () => { out.value = custom() && local.value ? new Date(local.value).toISOString() : ''; });
  }
})();
`;

export const APP_CSS = `
:root{--bg:#fff;--fg:#1b1f24;--mut:#667;--line:#dde;--accent:#2a5bd7;--card:#f7f8fb;--bad:#b3261e;--good:#1b6e3a}
@media(prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8eaee;--mut:#99a;--line:#2b2f38;--accent:#7aa2ff;--card:#1c1f26;--bad:#ff8a80;--good:#7ddc9c}}
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg)}
a{color:var(--accent)}header{display:flex;gap:1rem;align-items:center;justify-content:space-between;padding:.75rem 1rem;border-bottom:1px solid var(--line);flex-wrap:wrap}
header nav{display:flex;gap:1rem;align-items:center;flex-wrap:wrap}.brand{font-weight:700;text-decoration:none}
main{max-width:56rem;margin:0 auto;padding:1rem}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.5rem;border-bottom:1px solid var(--line);vertical-align:top}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:1rem;margin:1rem 0}.narrow{max-width:24rem;margin:3rem auto}
label{display:block;margin:.5rem 0}input,select,button{font:inherit;padding:.4rem .6rem}input:not([type=file]):not([type=checkbox]),select{width:100%;max-width:28rem;display:block}label.check{display:flex;gap:.5rem;align-items:baseline}fieldset{border:1px solid #ddd;margin:.75rem 0}
button{cursor:pointer}button.link{background:none;border:0;color:var(--accent);padding:0;text-decoration:underline}.inline{display:inline}
.preview{width:100%;height:24rem;border:1px solid var(--line);border-radius:8px}.badge{font-size:.75rem;border:1px solid var(--line);border-radius:99px;padding:.1rem .5rem}
.badge.live{color:var(--good)}.error{color:var(--bad)}.ok{color:var(--good)}small{color:var(--mut)}.history{padding-left:1.2rem}.history li{margin:.75rem 0}
.diff{background:var(--card);padding:.5rem;overflow:auto}.add{color:var(--good)}.del{color:var(--bad)}.wide{max-width:100%}.warn{border-color:var(--bad)}
`;

// Server-rendered dashboard: HTML plus a few lines of vanilla JS. No build step.
import { esc } from './util.js';

// Rule 8: the preview iframe is sandboxed by attribute as well as by the response header, and never
// gets allow-same-origin, so the dashboard never renders space content same-origin.
export const PREVIEW_SANDBOX = 'allow-scripts allow-forms allow-popups allow-modals allow-downloads';

const fmtBytes = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n > 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);
// Stored times are UTC ISO; the UTC text is the no-JS fallback and app.js shows the viewer's local time.
export const fmtTime = (t) => (t ? `<time datetime="${esc(t)}">${esc(t.slice(0, 16).replace('T', ' '))} UTC</time>` : '');

export function layout(title, cred, body, { nav = true } = {}) {
  const csrf = cred?.csrf ? `<meta name="csrf" content="${esc(cred.csrf)}">` : '';
  const admin = cred?.user?.role === 'admin';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · freespace</title>${csrf}<link rel="stylesheet" href="/assets/app.css"><script src="/assets/app.js" defer></script></head>
<body>${nav && cred ? `<header><a class="brand" href="/">freespace</a><nav><a href="/">Spaces</a><a href="/access">Access</a>${admin ? '<a href="/team">Team</a><a href="/instance">Instance</a>' : ''}
<form method="post" action="/api/logout" class="inline">${hidden(cred)}<input type="hidden" name="_next" value="/login"><button class="link">Sign out (${esc(cred.user.display_name || cred.user.username)})</button></form></nav></header>` : ''}
<main>${body}</main></body></html>`;
}
const hidden = (cred) => (cred?.csrf ? `<input type="hidden" name="_csrf" value="${esc(cred.csrf)}">` : '');

export function authPage(title, cred, error, fields, action, button, extra = '') {
  return layout(title, cred, `<section class="card narrow"><h1>${esc(title)}</h1>${error ? `<p class="error">${esc(error)}</p>` : ''}
<form method="post" action="${action}">${extra}${fields}<button>${esc(button)}</button></form></section>`, { nav: false });
}
const field = (name, label, type = 'text', attrs = '') => `<label>${esc(label)}<input name="${name}" type="${type}" ${attrs} required></label>`;
export const loginFields = field('email', 'Email', 'email', 'autocomplete="username"') + field('password', 'Password', 'password', 'autocomplete="current-password"');
export const setupFields = field('name', 'Your name') + field('email', 'Email', 'email', 'autocomplete="username"') + field('password', 'Password (10+ characters)', 'password', 'minlength="10" autocomplete="new-password"');

export function spacesPage(cred, spaces) {
  const rows = spaces.map((s) => `<tr><td><a href="/spaces/${esc(s.slug)}">${esc(s.name)}</a><br><small>/s/${esc(s.slug)}/</small></td>
<td><span class="badge ${esc(s.privacy)}">${s.privacy === 'team' ? 'Team only' : s.privacy === 'public' ? 'Public' : 'Anyone with the link'}</span></td>
<td>${s.live_number ? `v${s.live_number} by ${esc(s.live_author)}<br><small>${fmtTime(s.live_at)}</small>` : '<small>nothing published</small>'}</td></tr>`).join('');
  return layout('Spaces', cred, `<h1>Spaces</h1>
<table><thead><tr><th>Space</th><th>Who can view</th><th>Last published</th></tr></thead><tbody>${rows || '<tr><td colspan="3">No spaces yet.</td></tr>'}</tbody></table>
<section class="card"><h2>New space</h2><form method="post" action="/api/spaces">${hidden(cred)}<input type="hidden" name="_next" value="__space__">${field('name', 'Name')}<button>Create</button></form></section>`);
}

export function spacePage(cred, space, versions, warnings, links) {
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
<section class="card"><h2>Who can view</h2><form method="post" action="/api/spaces/${esc(space.slug)}">${hidden(cred)}<input type="hidden" name="_method" value="PATCH"><input type="hidden" name="_next" value="/spaces/${esc(space.slug)}">
<select name="privacy">${[['team', 'Team only'], ['link', 'Anyone with the link'], ['public', 'Public']].map(([v, l]) => `<option value="${v}"${space.privacy === v ? ' selected' : ''}>${l}</option>`).join('')}</select>
<button>Save</button></form><small>Team members can always view. Switching away from “Anyone with the link” pauses its links; switching back restores them. A link created while the space is team-only switches it to “Anyone with the link”; links paused earlier stay paused until you resume them.</small></section>
${links ? sharing(cred, space, links) : ''}
<section class="card"><h2>History</h2><ol class="history">${hist || '<li>No versions.</li>'}</ol></section>`);
}

export function diffPage(cred, space, d, texts) {
  const list = (title, items, f) => (items.length ? `<h3>${title}</h3><ul>${items.map(f).join('')}</ul>` : '');
  const td = texts.map(({ path, ops }) => `<h4>${esc(path)}</h4>${ops ? `<pre class="diff">${ops.filter(([o]) => o !== ' ').map(([o, l]) => `<span class="${o === '+' ? 'add' : 'del'}">${o} ${esc(l)}</span>`).join('\n')}</pre>` : '<p><small>Too large or not text.</small></p>'}`).join('');
  return layout(`Diff ${space.name}`, cred, `<h1>${esc(space.name)}: v${d.from} → v${d.to}</h1><p><a href="/spaces/${esc(space.slug)}">Back</a></p>
${list('Added', d.added, (f) => `<li>${esc(f.path)} <small>${fmtBytes(f.size)}</small></li>`)}${list('Removed', d.removed, (f) => `<li>${esc(f.path)}</li>`)}${list('Changed', d.changed, (f) => `<li>${esc(f.path)} <small>${fmtBytes(f.from)} → ${fmtBytes(f.to)}</small></li>`)}
${!d.added.length && !d.removed.length && !d.changed.length ? '<p>No differences.</p>' : ''}${td}`);
}

export function teamPage(cred, users, invites, created) {
  return layout('Team', cred, `<h1>Team</h1>
${created ? `<section class="card ok"><p>Invite link (shown once, valid 7 days):</p><input readonly class="wide" value="${esc(created)}"></section>` : ''}
<table><thead><tr><th>Person</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead><tbody>${users.map((u) => `<tr><td>${esc(u.display_name)}<br><small>${esc(u.username)}</small></td><td>${esc(u.role)}${u.disabled_at ? ' (disabled)' : ''}</td><td>${fmtTime(u.last_login_at)}</td>
<td>${!u.disabled_at && u.id !== cred.userId ? `<form method="post" action="/api/users/${esc(u.id)}/disable" class="inline">${hidden(cred)}<input type="hidden" name="_next" value="/team"><button class="link">Disable</button></form>` : ''}</td></tr>`).join('')}</tbody></table>
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

export function instancePage(cred, stats, gc, dcr, brand) {
  return layout('Instance', cred, `<h1>Instance</h1><ul><li>${stats.spaces} spaces, ${stats.versions} versions, ${stats.users} people</li><li>${fmtBytes(stats.bytesReferenced)} referenced in blob storage</li></ul>
${gc ? `<p class="ok">GC removed ${gc.removed} file(s), freed ${fmtBytes(gc.freed)}.</p>` : ''}
<form method="post" action="/api/admin/gc">${hidden(cred)}<input type="hidden" name="_next" value="/instance?gc=1"><button>Run GC</button></form>
<p><small>Garbage collection also runs lazily after publishes and deletes (at most every few hours). There are no background timers.</small></p>
<section class="card"><h2>Dynamic client registration</h2><p>${dcr ? 'On' : 'Off'}. Clients normally identify themselves with a metadata URL; turn this on only for clients that need RFC 7591 registration.</p>
<form method="post" action="/api/admin/dcr">${hidden(cred)}<input type="hidden" name="_next" value="/instance"><input type="hidden" name="enabled" value="${dcr ? '0' : '1'}"><button>${dcr ? 'Turn off' : 'Turn on'}</button></form></section>
<section class="card"><h2>Branding</h2><p>Shown to clients on the password, not-found and expired-link pages.</p>
<form method="post" action="/api/admin/branding">${hidden(cred)}<label>Agency name <input name="name" value="${esc(brand.name)}" maxlength="100"></label>
<label>Logo URL <input type="url" name="logo" value="${esc(brand.logo)}" placeholder="https://…"></label>
<label>Accent colour <input type="color" name="accent" value="${esc(brand.accent || '#1a73e8')}"></label><button>Save branding</button></form></section>`);
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
      const q = f.elements.message.value ? '?message=' + encodeURIComponent(f.elements.message.value) : '';
      const r = await fetch(f.dataset.upload + q, {
        method: 'POST', body: file,
        headers: { 'Content-Type': 'application/zip', 'X-CSRF-Token': document.querySelector('meta[name=csrf]').content },
      });
      if (r.ok) location.reload();
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

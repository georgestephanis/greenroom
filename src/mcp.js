// MCP over Streamable HTTP (JSON responses, no SSE), issue #214 section 7.
// Every tool checks the credential's scope; a missing scope is HTTP 403 insufficient_scope naming
// what to ask for, so the client can step up through /oauth/authorize.
import { httpErr, can } from './auth.js';
import { SLUG_RE } from './util.js';

const PROTOCOL = '2025-06-18';
const slugArg = { slug: { type: 'string', description: 'Space slug' } };
const obj = (props, required = Object.keys(props)) => ({ type: 'object', properties: props, required });

export const TOOLS = [
  { name: 'list_spaces', description: 'List the spaces this credential can see.', inputSchema: obj({}) },
  { name: 'get_space', description: 'Get one space and its live version.', inputSchema: obj(slugArg) },
  { name: 'create_space', description: 'Create a space (needs spaces:create). It is added to this grant.', inputSchema: obj({ name: { type: 'string' }, slug: { type: 'string' } }, ['name']) },
  {
    name: 'publish',
    description: 'Publish a new version. Files carry content (utf-8), base64, or the sha256 of an existing blob. Without base the version holds exactly these files; with base ("live" or a version number) it starts from that version, then applies files and delete.',
    inputSchema: obj({
      ...slugArg,
      files: { type: 'array', items: obj({ path: { type: 'string' }, content: { type: 'string' }, base64: { type: 'string' }, sha256: { type: 'string' } }, ['path']) },
      delete: { type: 'array', items: { type: 'string' } },
      base: { type: ['string', 'integer'] },
      message: { type: 'string' },
    }, ['slug']),
  },
  { name: 'read_file', description: 'Read a file from the live version (or version N).', inputSchema: obj({ ...slugArg, path: { type: 'string' }, version: { type: 'integer' } }, ['slug', 'path']) },
  { name: 'list_versions', description: 'Version history, newest first.', inputSchema: obj(slugArg) },
  { name: 'diff_versions', description: 'Files added, removed and changed between two versions.', inputSchema: obj({ ...slugArg, from: { type: 'integer' }, to: { type: 'integer' } }) },
  { name: 'rollback', description: 'Make an earlier version live again (as a new version).', inputSchema: obj({ ...slugArg, version: { type: 'integer' } }) },
  {
    name: 'create_share_link',
    description: 'Create a share link for a client and return its URL (shown only this once). A team-only space switches to "Anyone with the link". Optional expiry (ISO date), password and max uses.',
    inputSchema: obj({ ...slugArg, label: { type: 'string' }, expires_at: { type: 'string' }, password: { type: 'string' }, max_uses: { type: 'integer' } }, ['slug']),
  },
  { name: 'revoke_share_link', description: 'Revoke a share link; anyone holding it loses access at once.', inputSchema: obj({ ...slugArg, id: { type: 'string', description: 'Link id from create_share_link' } }) },
];

// The challenge asks for what the grant already has plus what is missing, so a client that steps up
// with exactly this scope widens the grant instead of replacing it with the one missing piece.
function insufficient(cred, need) {
  const sc = cred.scope;
  const have = [...(sc.spaces === '*' ? [] : sc.spaces.map((s) => `space:${s}`)), ...(sc.create ? ['spaces:create'] : []), ...sc.perms];
  return Object.assign(httpErr(403, `This credential needs scope: ${need.join(' ')}`), { insufficientScope: [...new Set([...have, ...need])].join(' ') });
}

export function createMcp({ store, db }) {
  const inScope = (cred, slug) => cred.scope.spaces === '*' || cred.scope.spaces.includes(slug);
  // A scoped credential gets the same answer for a space outside its scope and one that doesn't exist,
  // so it can't probe which slugs are taken.
  function space(cred, slug, perm) {
    slug = String(slug || '');
    if (!SLUG_RE.test(slug)) throw httpErr(404, 'No such space');
    const need = [];
    if (!inScope(cred, slug)) need.push(`space:${slug}`);
    if (perm && !can({ scope: { ...cred.scope, spaces: '*' } }, perm)) need.push(perm);
    if (need.length) throw insufficient(cred, need);
    const s = store.space(slug);
    if (!s) throw httpErr(404, 'No such space');
    return s;
  }
  const pubSpace = (s) => ({ slug: s.slug, name: s.name, privacy: s.privacy, url: `/s/${s.slug}/`, live_version: s.live_number ?? null });
  const pubVersion = (v) => ({ number: v.number, message: v.message, author: v.author_name, source: v.source, files: v.total_files, bytes: v.total_bytes, created_at: v.created_at });

  const pubLink = (origin, s, g) => ({ id: g.id, label: g.name, url: g.key ? `${origin}/s/${s.slug}/?key=${g.key}` : undefined, password: !!g.secret_hash, expires_at: g.expires_at, max_uses: g.max_uses, revoked_at: g.revoked_at });

  const tools = {
    list_spaces: (cred) => ({ spaces: store.listSpaces(cred.scope.spaces).map(pubSpace) }),
    get_space: (cred, a) => {
      const s = space(cred, a.slug);
      return { space: pubSpace(store.listSpaces([s.slug])[0] || s) };
    },
    create_space: (cred, a) => {
      if (!can(cred, 'create')) throw insufficient(cred, ['spaces:create']);
      // The new space joins this grant's scope (same row for OAuth and pasted tokens). Re-read the row in
      // one transaction so a concurrent create, re-consent or revocation is never overwritten.
      db.exec('BEGIN IMMEDIATE');
      try {
        const row = db.prepare('SELECT scope_json FROM api_keys WHERE id = ? AND revoked_at IS NULL').get(cred.id);
        if (!row) throw httpErr(401, 'This credential has been revoked');
        const s = store.createSpace(cred, { name: a.name, slug: a.slug });
        const sc = JSON.parse(row.scope_json);
        if (sc.spaces !== '*') db.prepare('UPDATE api_keys SET scope_json = ? WHERE id = ?').run(JSON.stringify({ ...sc, spaces: [...sc.spaces, s.slug] }), cred.id);
        db.exec('COMMIT');
        return { space: pubSpace(s) };
      } catch (e) { db.exec('ROLLBACK'); throw e; }
    },
    publish: async (cred, a) => {
      const s = space(cred, a.slug, 'publish');
      const v = await store.publish(cred, s, { files: a.files || [], remove: a.delete || [], base: a.base, message: a.message, source: 'mcp' });
      return { version: pubVersion(v), warnings: v.warnings };
    },
    read_file: async (cred, a) => {
      const s = space(cred, a.slug, 'read');
      const v = a.version ? store.versions(s.id).find((x) => x.number === Number(a.version)) : { id: s.live_version_id };
      const f = v?.id && store.file(v.id, String(a.path || '').replace(/^\/+/, ''));
      if (!f) throw httpErr(404, 'No such file');
      if (f.size > 5 * 1024 * 1024) throw httpErr(413, 'File too large to read here');
      const buf = await store.cas.read(f.sha256);
      const text = /^text\/|json|javascript|xml|svg/.test(f.content_type);
      return { path: f.path, content_type: f.content_type, size: f.size, sha256: f.sha256, ...(text ? { content: buf.toString('utf8') } : { base64: buf.toString('base64') }) };
    },
    list_versions: (cred, a) => ({ versions: store.versions(space(cred, a.slug, 'read').id).map(pubVersion) }),
    diff_versions: (cred, a) => store.diff(space(cred, a.slug, 'read'), a.from, a.to),
    rollback: async (cred, a) => ({ version: pubVersion(await store.rollback(cred, space(cred, a.slug, 'publish'), a.version, 'mcp')) }),
    // Share links need the share scope. There is deliberately no tool that makes a space Public.
    create_share_link: async (cred, a, origin) => {
      const s = space(cred, a.slug, 'share');
      return { link: pubLink(origin, s, await store.createLink(cred, s, a)) };
    },
    revoke_share_link: (cred, a, origin) => {
      const s = space(cred, a.slug, 'share');
      return { link: pubLink(origin, s, store.revokeLink(cred, s, a.id)) };
    },
  };

  /** One JSON-RPC message in, { status, body, headers } out. */
  return async function handle(cred, msg, origin) {
    const reply = (result) => ({ status: 200, body: { jsonrpc: '2.0', id: msg.id, result } });
    if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return { status: 400, body: { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request' } } };
    if (msg.id === undefined) return { status: 202 }; // notification
    switch (msg.method) {
      case 'initialize': // ponytail: one supported version; answer with it whatever the client asked for
        return reply({ protocolVersion: PROTOCOL, capabilities: { tools: {} }, serverInfo: { name: 'freespace', version: '0.3.0' } });
      case 'ping': return reply({});
      case 'tools/list': return reply({ tools: TOOLS });
      case 'tools/call': {
        const fn = tools[msg.params?.name];
        if (!fn) return { status: 200, body: { jsonrpc: '2.0', id: msg.id, error: { code: -32602, message: 'Unknown tool' } } };
        try {
          const out = await fn(cred, msg.params.arguments || {}, origin);
          return reply({ content: [{ type: 'text', text: JSON.stringify(out) }], structuredContent: out });
        } catch (e) {
          if (e.insufficientScope) return { status: 403, insufficientScope: e.insufficientScope, body: { jsonrpc: '2.0', id: msg.id, error: { code: -32001, message: e.message } } };
          if (!e.status) throw e;
          return reply({ content: [{ type: 'text', text: e.message }], isError: true });
        }
      }
      default:
        return { status: 200, body: { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'Method not found' } } };
    }
  };
}

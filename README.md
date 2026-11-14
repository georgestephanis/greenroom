# freespace

A small, self-hosted place for a team (3–10 people) to host the things their LLM agents make: reports, dashboards, prototypes, docs. Publish a folder of static files, get a URL, keep every version, roll back in a click.

- **Static spaces** served at `/s/{slug}/`, with clean URLs, `_redirects` and `_headers`.
- **Versioned**: every publish is an immutable version over a content-addressed blob store; "live" is a pointer. Rollback makes a new version.
- **Team login** with a dashboard: spaces, history, diffs, zip upload, invites, who-can-view.
- **Agents over MCP**: point an MCP client at `/mcp`; it signs in with OAuth and asks a team member for scoped access. Pasted tokens work too. History shows who did what, e.g. "Claude (via Ada)".
- **One file of state**: SQLite (`node:sqlite`) plus a blob directory. No native dependencies, no timers, no background workers.
- Node 24+, GPL-3.0-or-later.

This release covers milestones M0–M2: the core, plus OAuth and MCP. Share links and the "Anyone with the link" mode (M3), export (M4) and a publishing CLI are not built yet.

## Run it

```bash
node bin/freespace.js serve          # http://127.0.0.1:8080
```

Open it, create the admin account at `/setup`, then invite your team from the Team page. Put a TLS-terminating proxy in front for real use (the session cookie is `Secure`; browsers allow it on `localhost` for trying things out). A sample unit file is in `deploy/freespace.service`.

| Variable | Default | |
|---|---|---|
| `FREESPACE_DATA_DIR` | `./data` | database, blobs, signing secret |
| `HOST` / `PORT` | `127.0.0.1` / `8080` | |
| `FREESPACE_PUBLIC_URL` | | used for invite links and as the OAuth issuer; set it in production |
| `FREESPACE_TRUST_PROXY` | | `1` behind a proxy that sets `X-Forwarded-For`, so login throttling sees real client IPs |
| `FREESPACE_MAX_UPLOAD_BYTES` | 200 MB | also `..._MAX_FILE_BYTES`, `..._MAX_SPACE_BYTES`, `..._MAX_TOTAL_BYTES` |

It idles at well under 100 MB of RAM; `npm test` boots it with a 256 MB heap cap and checks RSS.

## Security model: path mode

Spaces share one origin with the dashboard, so isolation is enforced by headers, not by hostnames:

1. Every response under `/s/` carries `Content-Security-Policy: sandbox allow-scripts allow-forms allow-popups allow-modals allow-downloads`, so each page runs in an opaque origin (no `allow-same-origin`, no top navigation). Also `nosniff` and `Referrer-Policy: no-referrer`.
2. `_headers` can't set CSP, `Set-Cookie`, `Service-Worker-Allowed`, `Cross-Origin-*` or `Access-Control-*`; they're dropped with a warning when the version is finalised.
3. The dashboard session cookie is `__Host-fs_session; HttpOnly; Secure; SameSite=Strict`.
4. State-changing requests need a CSRF token and `Sec-Fetch-Site: same-origin`; `Origin: null` is refused. Bearer-token requests are exempt.
5. Cookies set by plugins are rewritten to `Path=/s/{slug}/` with a per-space name prefix.
6. Viewing a non-public space uses a viewer cookie bound by HMAC to that space's id. A cookie for one space is useless on another, and removing a member revokes access immediately.
7. Per-document write tokens for the future data API are injected into documents only.
8. The dashboard's preview iframe has a `sandbox` attribute without `allow-same-origin`.

Trade-offs you will notice: pages can't use their own `localStorage` or cookies (they're sandboxed), and absolute paths like `/app.css` must become relative (`app.css`) or be mapped with `_redirects`.

## Agents: MCP and OAuth

The MCP endpoint is `POST /mcp` (Streamable HTTP, JSON responses). Tools: `list_spaces`, `get_space`, `create_space`, `publish`, `read_file`, `list_versions`, `diff_versions`, `rollback`.

Every way in — dashboard session, OAuth access token, pasted `fsa_` token — resolves to one credential object before any route runs, and every check reads only that.

- **Discovery.** An unauthenticated `/mcp` call gets `401` with `WWW-Authenticate: Bearer resource_metadata=…` (RFC 9728), which points at `/.well-known/oauth-authorization-server` (RFC 8414).
- **Clients** identify themselves with a Client ID Metadata Document: `client_id` is an https URL whose JSON lists its name and redirect URIs. It is fetched with public addresses only (checked at connect time, so DNS rebinding can't reach private ranges), no redirects, 64 KB and 5 s limits. Dynamic client registration is off unless an admin turns it on (Instance page).
- **Authorization code + PKCE (S256 only).** The consent screen shows the client's name and metadata URL, a space picker, a "can create spaces" toggle and a permission picker. Codes live two minutes and work once; replaying one revokes what it issued.
- **Tokens** are opaque, stored as SHA-256 hashes, and found with one indexed lookup. Access tokens last an hour. Refresh tokens rotate on every use; presenting a spent one revokes the whole grant.
- **One grant per member and client**, stored as a row in the same table as pasted tokens, so the Access page lists both, grouped by client. Revoking a grant kills its access and refresh tokens at once. Asking for more (`insufficient_scope` → re-consent) widens the same grant.
- **The granter is live.** Disable a member and every grant and token they approved stops working.
- **Scopes:** `space:{slug}`, `spaces:create`, `publish`, `db`, `share`, `export`, `read`. Any other string fails the request. A tool call outside the credential's scope returns `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"` naming what to ask for.
- A space an agent creates joins that agent's grant, and only that one.

Anything that escalates privileges needs a person's own signed-in session, never a scoped credential: inviting people, disabling users, minting tokens, approving OAuth grants, instance settings, and making a space public. No MCP tool does any of these.

## Develop

```bash
npm test           # node:test, no dependencies to install
npm run check      # fails if anything imports outside this directory
```

See `CONTRIBUTING.md`.

## AI disclosure

This project was written with substantial help from Claude (Anthropic) via Claude Code, working from a human-written specification. A person directed the work and is responsible for it; the tests and the security model above are the things to review first.

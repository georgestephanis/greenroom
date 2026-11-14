# freespace

A small, self-hosted place for a team (3–10 people) to host the things their LLM agents make: reports, dashboards, prototypes, docs. Publish a folder of static files, get a URL, keep every version, roll back in a click.

- **Static spaces** served at `/s/{slug}/`, with clean URLs, `_redirects` and `_headers`.
- **Versioned**: every publish is an immutable version over a content-addressed blob store; "live" is a pointer. Rollback makes a new version.
- **Team login** with a dashboard: spaces, history, diffs, zip upload, invites, who-can-view.
- **One file of state**: SQLite (`node:sqlite`) plus a blob directory. No native dependencies, no timers, no background workers.
- Node 24+, AGPL-3.0-or-later.

This release covers the core (milestones M0 and M1). Agent tokens, OAuth/MCP and a publishing CLI (M2), and share links (M3) are not built yet; the schema is ready for them.

## Run it

```bash
node bin/freespace.js serve          # http://127.0.0.1:8080
```

Open it, create the admin account at `/setup`, then invite your team from the Team page. Put a TLS-terminating proxy in front for real use (the session cookie is `Secure`; browsers allow it on `localhost` for trying things out). A sample unit file is in `deploy/freespace.service`.

| Variable | Default | |
|---|---|---|
| `FREESPACE_DATA_DIR` | `./data` | database, blobs, signing secret |
| `HOST` / `PORT` | `127.0.0.1` / `8080` | |
| `FREESPACE_PUBLIC_URL` | | used for invite links |
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

Anything that escalates privileges (inviting people, disabling users, making a space public, minting tokens later) needs a person's own signed-in session, never a scoped credential.

## Develop

```bash
npm test           # node:test, no dependencies to install
npm run check      # fails if anything imports outside this directory
```

See `CONTRIBUTING.md`.

## AI disclosure

This project was written with substantial help from Claude (Anthropic) via Claude Code, working from a human-written specification. A person directed the work and is responsible for it; the tests and the security model above are the things to review first.

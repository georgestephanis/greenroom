# freespace bundle format, version 1

A bundle is a plain zip. It is the contract between freespace instances today and between freespace
and homefast later, so it stays small, versioned and boring. The committed fixtures in
`test/fixtures/bundles/` (regenerate with `node scripts/make-fixtures.js`) are the reference examples.

## Two kinds

**`{slug}.freespace.zip`** (`kind: "current"`): the live version only.

```
space.json
site/…                  the live version's files, browsable as-is
plugins/{name}/…        each enabled plugin's current data (none yet; see Plugins)
```

**`{slug}.freespace-history.zip`** (`kind: "history"`): the above, plus

```
history/versions.json   every version, oldest first
history/blobs/ab/{sha256}   every unique blob any version uses (content-addressed)
history/plugins/{name}/…    plugin history (none yet)
history/history.fi      git fast-import stream, informational
activity.json           the space's audit trail
```

## `space.json`

```json
{
  "format": "freespace-bundle/1",
  "kind": "current | history",
  "exported_at": "2025-03-03T10:00:00.000Z",
  "generator": { "name": "freespace", "version": "0.4.0" },
  "space": {
    "id": "spc_…", "slug": "acme-site", "name": "Acme site",
    "privacy": "team | link | public", "noindex": true, "owner_id": "usr_…",
    "created_at": "…", "updated_at": "…", "live_version_id": "ver_…", "plugins": []
  },
  "live_version": { "id": "ver_…", "number": 7, "author": "Claude (via Ada)", "source": "mcp", "message": "…", "created_at": "…" }
}
```

`live_version` is present in both kinds. A reader must refuse any `format` it does not know.
Timestamps are ISO-8601 UTC. IDs use homefast's prefixes (`spc_`, `ver_`, `usr_`, `key_`).

## `history/versions.json`

`[{ id, number, parent, author, author_id, source, message, created_at, files: [{ path, sha256, size, type }] }]`

- `parent` is a version id or `null`; it must refer to an earlier version in the same file.
- `author` is a display name: a person, or an agent as "Claude (via Ada)".
- `files[].sha256` names the blob at `history/blobs/{first two hex}/{sha256}`.

## What is left out, on purpose

- **Share links**: their keys, labels, passwords, expiry, use counts and view logs. Recreate them on the
  new instance. `privacy: "link"` is kept, so the space stays closed until a link exists.
- **Password hashes, session cookies, API keys, OAuth grants and tokens**, and the instance secret.
- **Users.** Only opaque ids appear (`owner_id`, `author_id`, activity `actor_id`), never emails or names beyond the
  author display string.
- **Routing**: `_redirects` and `_headers` travel as ordinary site files; the importer compiles them again.
- Anything under a `.git` path component is omitted from `history.fi` (git cannot store it). It stays in the blobs.

## `history/history.fi`

A `git fast-import` stream on `refs/heads/main`: one commit per version in version order, with the
version's author, message and timestamp (agents show as "Claude (via X)"), trailers
`Freespace-Version`, `Freespace-Source` and (when it has one) `Freespace-Parent`, and a placeholder email
(`…@freespace.invalid`). The branch is always linear: each commit follows the previous version and carries the
files as a delta from it, so a version published on an older base (or a restart with no parent) still shows up in
`git log`. The real parent is only in the `Freespace-Parent` trailer. The importer ignores this file; it exists so a space's history can be read with git:

```bash
git init site && cd site && git fast-import < history.fi && git checkout -f main
```

## `activity.json`

`[{ actor_kind, actor_id, action, resource_type, resource_id, detail, created_at }]`, oldest first. `detail` is
the same small JSON the instance logged.

## Importing (freespace)

`POST /api/import[?slug=…&replace=1]` with the zip as the body, or the Import card on the Spaces page. Signed-in
people only; agent credentials cannot import or replace.

- Treated as untrusted. Paths must already be clean (no `..`, no leading `/`, no `//`, no duplicates); sizes
  declared in the zip and in the manifest must be true; every blob is re-hashed while it is stored; a version's
  parent must exist; limits (`maxFileBytes`, `maxSpaceBytes`, entry count, JSON size) apply as for uploads.
  Nothing is written to the database until everything has checked out, and then in one transaction.
- **Never overwrites.** If the slug exists the import is refused (409). With `replace=1` the existing space's
  versions are replaced by the bundle's; its links, privacy and activity stay, and the import is logged.
- **IDs are preserved**, or remapped when they collide with a row already on this instance (a warning says so).
  The importer becomes the owner; `owner_id` and history `author_id` in the bundle are informational.
- A `current` bundle becomes a single version. Routing is recompiled, never taken from the bundle.
- Imported spaces are created with the bundle's privacy and `noindex`, and with no share links.

## Plugins (not yet)

Core is static-only. A bundle may list `plugins` in `space.json` and carry `plugins/{name}/…`; freespace today
imports the static site, skips that data and says so in the import warnings. The mapping into homefast, when
plugins exist: `sqlite` maps directly (`plugins/sqlite/app.sqlite` becomes homefast's `db/app.sqlite`),
`functions` needs a configuration translation, `php` has no equivalent and imports as static with a warning.

## For the homefast importer

Same IDs, same column names and types for `spaces`, `versions`, `manifest_files` and `activity_log`, UTC ISO
timestamps, and `privacy` mapping 1:1 to grants (`team` to team, `link` to share link, `public` to public).

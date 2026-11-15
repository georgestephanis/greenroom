# greenroom bundle format, version 1

A bundle is a plain zip. It is the contract between greenroom instances today and between greenroom
and Spacefast later, so it stays small, versioned and boring. The committed fixtures in
`test/fixtures/bundles/` (regenerate with `node scripts/make-fixtures.js`) are the reference examples.

## Two kinds

**`{slug}.greenroom.zip`** (`kind: "current"`): the live version only.

```
space.json
site/…                  the live version's files, browsable as-is
plugins/{name}/…        each plugin's current data, plus `settings.json` (see Plugins)
```

**`{slug}.greenroom-history.zip`** (`kind: "history"`): the above, plus

```
history/versions.json   every version, oldest first
history/blobs/ab/{sha256}   every unique blob any version uses (content-addressed)
history/plugins/{name}/…    plugin history (history bundles only)
history/history.fi      git fast-import stream, informational
activity.json           the space's audit trail
```

## `space.json`

```json
{
  "format": "greenroom-bundle/1",
  "kind": "current | history",
  "exported_at": "2025-03-03T10:00:00.000Z",
  "generator": { "name": "greenroom", "version": "0.4.0" },
  "space": {
    "id": "spc_…", "slug": "acme-site", "name": "Acme site",
    "privacy": "team | link | public", "noindex": true, "owner_id": "usr_…",
    "created_at": "…", "updated_at": "…", "live_version_id": "ver_…", "plugins": []
  },
  "live_version": { "id": "ver_…", "number": 7, "author": "Claude (via Ada)", "source": "mcp", "message": "…", "created_at": "…",
    "files": [{ "path": "index.html", "type": "text/html; charset=utf-8" }] }
}
```

`live_version` is present in both kinds; its `files` list carries each live file's content type (a current bundle has no other manifest, so the importer keeps these when they look like a MIME type). A reader must refuse any `format` it does not know.
Timestamps are ISO-8601 UTC. IDs use Spacefast's prefixes (`spc_`, `ver_`, `usr_`, `key_`).

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
`Greenroom-Version`, `Greenroom-Source` and (when it has one) `Greenroom-Parent`, and a placeholder email
(`…@greenroom.invalid`). The branch is always linear: each commit follows the previous version and carries the
files as a delta from it, so a version published on an older base (or a restart with no parent) still shows up in
`git log`. The real parent is only in the `Greenroom-Parent` trailer. The importer ignores this file; it exists so a space's history can be read with git:

```bash
git init site && cd site && git fast-import < history.fi && git checkout -f main
```

## `activity.json`

`[{ actor_kind, actor_id, action, resource_type, resource_id, detail, created_at }]`, oldest first. `detail` is
the same small JSON the instance logged; the importer adds `imported: true` to it.

## Importing (greenroom)

`POST /api/import[?slug=…&replace=1]` with the zip as the body, or the Import card on the Spaces page. Signed-in
people only; agent credentials cannot import or replace.

- Treated as untrusted. Paths must already be clean (no `..`, no leading `/`, no `//`, no duplicates); sizes
  declared in the zip and in the manifest must be true; every blob is re-hashed while it is stored; a version's
  parent must exist; limits (`maxFileBytes`, `maxSpaceBytes`, entry count, JSON size) apply as for uploads.
  Nothing is written to the database until everything has checked out, and then in one transaction.
- **Limits.** An import is capped at `GREENROOM_MAX_IMPORT_BYTES` (default three times `maxSpaceBytes` plus 64 MB: a history bundle carries each blob in `site/`, `history/blobs/` and `history.fi`), separate from the upload cap, so a space's own export always fits. One import runs at a time (503 + `Retry-After` otherwise). A bundle holds at most 65,534 entries and no zip64.
- **Never overwrites.** If the slug exists the import is refused (409). With `replace=1` the existing space's
  versions are replaced by the bundle's; its links, privacy and activity stay, and the import is logged. A taken slug is refused before any blob is stored.
- **IDs are preserved**, or remapped when they collide with a row already on this instance (a warning says so).
  The importer becomes the owner; `owner_id` and history `author_id` in the bundle are informational.
- A `current` bundle becomes a single version. Routing is recompiled, never taken from the bundle.
- Imported spaces are created with the bundle's privacy and `noindex`, and with no share links.

## Plugins

`space.json`'s `space.plugins` lists the plugins the space uses. Each owns `plugins/{name}/…` (current data) and
`history/plugins/{name}/…` (history bundles only). Core writes `plugins/{name}/settings.json`; the plugin writes the rest.

- `sqlite`: `plugins/sqlite/app.sqlite` (a consistent copy) and, in history bundles,
  `history/plugins/sqlite/snapshots.json` plus `snapshots/{sha256}.sqlite`.
- `watermark`: settings only.

On import, settings are validated against the plugin's spec. An installed plugin's own exporter and importer
handle its files even while it is switched off. A plugin that is not installed on the importing instance has its
files kept untouched (and re-exported later), with a warning. Plugin files count against the space size limit. Files for plugins the
space does not list are skipped. The mapping into Spacefast: `sqlite` maps directly (`plugins/sqlite/app.sqlite`
becomes `db/app.sqlite`); `watermark`'s banner setting is dropped with a warning; `functions` needs a
configuration translation and `php` has no equivalent (static import with a warning).

## For the Spacefast importer

Same IDs, same column names and types for `spaces`, `versions`, `manifest_files` and `activity_log`, UTC ISO
timestamps, and `privacy` mapping 1:1 to grants (`team` to team, `link` to share link, `public` to public).

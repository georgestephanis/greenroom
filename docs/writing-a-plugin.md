# Writing a freespace plugin

A plugin is one ES module whose default export comes from `definePlugin`. The smallest real one is
[`watermark`](../src/plugins/watermark.js); this guide walks through it.

```js
import { definePlugin } from '../plugins.js';
import { esc } from '../util.js';

export default definePlugin({
  name: 'watermark',
  version: '1.0.0',
  description: 'Show a confidentiality banner, with the client name, on pages opened through a share link.',
  spaceSettings: {
    text: { type: 'string', default: 'Confidential — prepared for {client}', max: 200, label: '…' },
    position: { type: 'enum', values: ['top', 'bottom'], default: 'top', label: 'Position' },
  },
  register(ctx) {
    ctx.transform(({ html, viewer, settings }) => {
      if (viewer.kind !== 'link') return;           // return nothing = leave the page alone
      …build the banner with esc(...)…
      return html.replace(…) ;                      // return the new HTML
    });
  },
});
```

## The pieces

- **`name`** is lowercase letters, digits and dashes. It names the data directory, the settings row and the bundle path.
- **`spaceSettings`** is a spec, not code. Types: `bool`, `string` (`max`), `number` (`min`, `max`), `enum` (`values`) and
  `map` (identifier keys to strings). Core validates every save and every import against it and draws the dashboard form from it.
  Settings arrive in your hooks already cleaned and defaulted.
- **`register(ctx)`** runs once, and must stay cheap: declare hooks, open nothing. Do heavy work (opening a database) inside a hook, on first use.

## What `ctx` offers

| Hook | What it does |
| --- | --- |
| `ctx.transform(fn)` | Rewrite HTML documents as they are served. `fn({html, viewer, settings, docToken})` returns new HTML or nothing. `viewer.kind` is `team`, `link` (with `viewer.label`, the share link's label) or `public`. Only document loads of 200 HTML responses up to 8 MB are offered; stored files never change. |
| `ctx.serve({path, methods, auth, handler})` | A route under `/s/{slug}/_fs/…`. `auth: 'token'` needs the short-lived document token core puts in pages (`ctx.transform` + `docToken()`); `'none'` is for public, secret-free assets. The handler gets parsed JSON and returns `{json}` or `{type, body}`. Core answers CORS (opaque origin only, no credentials) itself. |
| `ctx.mcp.tool(name, {description, inputSchema, perm}, handler)` | An MCP tool. Core resolves the credential and checks `perm` (`read`, `publish`, `db`, …) for the space before your handler runs; you never receive the credential. |
| `ctx.on('version.created' \| 'space.deleted', fn)` | Events. Errors are logged, never fatal. |
| `ctx.export(fn)` / `ctx.import(fn)` | Add files to both export zips; read them back on import. Core handles `settings.json`. |
| `ctx.blobs(fn)` | Return CAS hashes you still need, so garbage collection keeps them. |
| `ctx.dir(space)`, `ctx.settings(space)`, `ctx.currentVersion(space)`, `ctx.cas` | Your own data directory per space, settings, the live version number, and a narrow content store (`storeStream`, `read`, `stream`, `has`). |

## What a plugin cannot do

It gets no database handle, no credential, no session, and cannot mint or bypass any of them. Response headers you set are filtered
(CSP, `Set-Cookie` without rewriting, CORS and friends are core's), cookies are rewritten to the space's path and prefix, and
the sandbox CSP stays on every response. A hook runs only when the plugin is installed, enabled by an admin, and switched on for that space.

## Installing

Bundled plugins ship in `src/plugins/`. Others load from `FREESPACE_PLUGINS=/abs/a.js,/abs/b.js`. Enable on the Instance page,
then switch on per space. Keep untrusted code out: a plugin runs in the server process.

## Test it

See `test/plugins.test.js`: it boots an instance, enables the plugin, opens a share link and asserts on the HTML.

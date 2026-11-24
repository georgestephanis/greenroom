# The read-only tour

The tour at <https://georgestephanis.github.io/greenroom/> lets people click through greenroom's dashboard before installing it. Every page in it is a real greenroom page with sample data, saved as static HTML. Nothing in it can change anything: there is no server behind it.

## What's in it

- **Spaces**: three spaces. One is public, one is shared with a password-protected link, and one is team-only.
- **A space page** for each, with a live preview of the published site, upload and export, sharing, history and settings.
- **Diffs**: one page for each "Diff vs" link in a space's history.
- **Access**, **Team**, **Instance** and **Account**.

The sample data comes from the real API and MCP endpoint, not hand-written HTML:

- two people, Ada (admin) and Ben (member), plus one open invite
- an agent token named Claude, used over MCP, so history shows "Claude (via Ada)"
- the Q3 board report published twice by Claude, so it has a diff
- a share link on the board report with a password, a 7-day expiry and a 5-use limit

## How the static pages differ from the real ones

- `app.js` is replaced by `scripts/tour/tour.js`, which keeps the display touches (dates in your timezone, the current nav item, Copy buttons, the custom expiry field) but stops every form from submitting. Submitting shows a short "read-only tour" notice instead.
- A banner under the header explains the tour and links to [Run it](../README.md#run-it).
- Links to pages that aren't in the tour, such as export downloads and "Move spaces…", show a note instead of navigating.
- CSRF tokens are removed, and the host shown in share links and invites is `https://greenroom.example.com`.
- All links are relative, so the tour works under `/greenroom/` on GitHub Pages or from any other folder.

## Building it

```bash
node scripts/tour/build.js            # writes _tour/ (ignored by git)
node scripts/tour/build.js some/dir   # or any other folder
```

It starts a throwaway greenroom in a temporary directory on a random local port, fills it, saves the pages, and deletes the temporary directory. It needs nothing beyond Node 24. To look at the result, serve the folder with any static server, for example `python3 -m http.server --directory _tour`.

| File | What it is |
|---|---|
| `scripts/tour/build.js` | Seeds the data, saves and rewrites the pages |
| `scripts/tour/tour.js` | Stand-in for `app.js` on the static pages |
| `scripts/tour/tour.css` | The banner and notice styles, using the dashboard's colours |
| `scripts/tour/sample/` | The board report site the sample agent publishes |

## Deploying

`.github/workflows/tour.yml` builds the tour and deploys it to GitHub Pages on every push to `main`, so it always matches the current dashboard. The repo's Pages source is set to GitHub Actions.

CI (`.github/workflows/ci.yml`) also runs the build. A dashboard change that breaks the tour, for example by renaming a route the build fetches, fails the pull request rather than the deploy.

## Changing it

- **More sample data:** add API or MCP calls in the seeding section of `build.js`. Anything a page shows comes along automatically.
- **Another page:** add `[serverPath, fileInTour]` to the `pages` list. Links to it from other pages are rewritten automatically.
- **New client-side behaviour in `app.js`:** if the tour should show it too, copy it into `tour.js`, but keep anything that sends a request out.

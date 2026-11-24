# Contributing

greenroom is plain ESM JavaScript on Node 24+, with no dependencies and no build step.

```bash
npm test          # node:test, includes the path-mode security tests
npm run check     # fails if any file imports outside this directory
node scripts/tour/build.js   # builds the read-only tour into _tour/
```

- Keep it small. Prefer the standard library; adding a dependency needs a good reason.
- Dashboard changes show up in the [read-only tour](docs/read-only-tour.md) automatically. If one adds client-side behaviour to `app.js`, decide whether `scripts/tour/tour.js` needs it too.
- Any change that touches `/s/` responses needs a test in `test/security.test.js`.
- Commit messages should read well on their own: they are published as-is to the public mirror.
- By contributing you agree your work is licensed GPL-3.0-or-later.

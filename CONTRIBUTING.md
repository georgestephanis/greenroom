# Contributing

freespace is plain ESM JavaScript on Node 24+, with no dependencies and no build step.

```bash
npm test          # node:test, includes the path-mode security tests
npm run check     # fails if any file imports outside this directory
```

- Keep it small. Prefer the standard library; adding a dependency needs a good reason.
- Any change that touches `/s/` responses needs a test in `test/security.test.js`.
- Commit messages should read well on their own: they are published as-is to the public mirror.
- By contributing you agree your work is licensed AGPL-3.0-or-later.

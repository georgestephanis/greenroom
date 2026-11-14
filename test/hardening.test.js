// Regression tests for the #215 review findings.
import test from 'node:test';
import assert from 'node:assert/strict';
import { compilePattern, matchRule, parseHeadersFile } from '../src/routing.js';

test('redirect patterns: placeholders must be whole segments (no ReDoS)', () => {
  assert.throws(() => compilePattern('/:a:b'), /whole path segment/);
  assert.throws(() => compilePattern('/x/:a*'), /whole path segment/);
  assert.throws(() => compilePattern('/:a.html'), /whole path segment/);
  assert.throws(() => compilePattern('/:a/:b/:c/:d/:e/:f/:g/:h/:i'), /more than 8/);
  assert.ok(compilePattern('/blog/:year/:slug/*'));
  const t0 = Date.now();
  matchRule('/:a/:b/:c/:d/:e/:f/:g/:h', '/' + 'a/'.repeat(5000) + 'x', new URLSearchParams());
  assert.ok(Date.now() - t0 < 200);
});

test('_headers cannot set host-scoped headers', () => {
  const { blocks, diagnostics } = parseHeadersFile('/*\n  Strict-Transport-Security: max-age=0\n  Clear-Site-Data: "*"\n  Set-Login: logged-out\n  Permissions-Policy: camera=*\n  X-Ok: 1\n');
  assert.deepEqual(blocks[0].headers, [{ key: 'X-Ok', value: '1' }]);
  assert.equal(diagnostics.length, 4);
});

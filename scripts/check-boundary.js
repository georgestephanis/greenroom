// greenroom is self-contained: nothing may import from outside this directory (in particular ../core).
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const bad = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === 'data' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (/\.(c|m)?js$/.test(e.name)) {
      const src = fs.readFileSync(p, 'utf8');
      for (const m of src.matchAll(/(?:from\s+|import\s*\(\s*|require\s*\(\s*)['"](\.[^'"]*)['"]/g)) {
        if (!path.resolve(path.dirname(p), m[1]).startsWith(root + path.sep)) bad.push(`${path.relative(root, p)} imports ${m[1]}`);
      }
    }
  }
})(root);
if (bad.length) { console.error('Boundary violations:\n' + bad.join('\n')); process.exit(1); }
console.log('boundary ok');

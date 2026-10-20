// Fails if any production dependency of the panel has a licence that
// ADR-0008 does not allow. Dev tools are not shipped and are not checked.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const allowed = new Set([
  'MIT',
  'ISC',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'Apache-2.0',
  '0BSD',
  'Zlib',
  'Unlicense',
  'CC0-1.0',
  'OFL-1.1', // fonts (Vazirmatn)
]);
const forbidden = /\b(A?GPL|SSPL|LGPL|CC-BY-NC|Commons-Clause)/i;

// Run npm through node itself (npm_execpath is set by `npm run`), so no
// shell is involved on any platform.
const npmArgs = ['ls', '--omit=dev', '--all', '--json', '--long'];
const npmCli = process.env.npm_execpath;
const out = npmCli
  ? execFileSync(process.execPath, [npmCli, ...npmArgs], { encoding: 'utf8', maxBuffer: 64 << 20 })
  : execFileSync('npm', npmArgs, { encoding: 'utf8', maxBuffer: 64 << 20 });
const tree = JSON.parse(out);

const seen = new Map();
(function walk(deps) {
  for (const [name, d] of Object.entries(deps ?? {})) {
    const key = `${name}@${d.version}`;
    if (seen.has(key) || !d.path) continue;
    let license = d.license;
    if (!license) {
      try {
        license = JSON.parse(readFileSync(join(d.path, 'package.json'), 'utf8')).license;
      } catch {
        license = undefined;
      }
    }
    seen.set(key, typeof license === 'object' ? license.type : license);
    walk(d.dependencies);
  }
})(tree.dependencies);

// An SPDX expression passes when one of its OR-alternatives is allowed.
const ok = (expr) =>
  !!expr &&
  !forbidden.test(expr) &&
  expr
    .replace(/[()]/g, '')
    .split(/\s+OR\s+/)
    .some((alt) => alt.split(/\s+AND\s+/).every((l) => allowed.has(l.trim())));

const bad = [...seen].filter(([, l]) => !ok(l));
for (const [pkg, l] of [...seen].sort()) console.log(`${ok(l) ? 'ok ' : 'BAD'}  ${l ?? 'UNKNOWN'}  ${pkg}`);
if (bad.length) {
  console.error(`\n${bad.length} package(s) with a licence not allowed by ADR-0008`);
  process.exit(1);
}
console.log(`\n${seen.size} production packages, all licences allowed`);

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
// @vulnify/sdk@0.2.0 packs as vulnify-sdk-0.2.0.tgz. npm pack always runs prepare, so --json is mixed with the build log.
const tarball = join(root, `${pkg.name.replace('@', '').replace('/', '-')}-${pkg.version}.tgz`);

function run(args) {
  execFileSync(args[0], args.slice(1), { cwd: root, stdio: 'inherit' });
}

console.log('\n== npm pack --dry-run ==\n');
run(['npm', 'pack', '--dry-run']);

console.log('\n== npm pack ==\n');
run(['npm', 'pack']);
const dir = mkdtempSync(join(tmpdir(), 'vulnify-sdk-smoke-'));

const decision = {
  id: '1',
  decision: 'ALLOW',
  evaluatedDecision: 'ALLOW',
  monitored: false,
  review: null,
  riskLevel: 'LOW',
  riskScore: 1,
  reasons: [],
  policy: null,
};

try {
  execFileSync('npm', ['init', '-y'], { cwd: dir, stdio: 'inherit' });
  execFileSync('npm', ['install', '--no-save', '--no-fund', '--no-audit', tarball], {
    cwd: dir,
    stdio: 'inherit',
  });

  writeFileSync(
    join(dir, 'cjs.cjs'),
    `const { Vulnify } = require('@vulnify/sdk');
if (typeof Vulnify !== 'function') throw new Error('CJS require did not export Vulnify');
let url;
global.fetch = async (input) => {
  url = String(input);
  return { ok: true, status: 200, json: async () => (${JSON.stringify(decision)}) };
};
(async () => {
  const result = await new Vulnify({ apiKey: 'k', retries: 0 }).check({ action: 'READ_DATA' });
  if (result.decision !== 'ALLOW') throw new Error('unexpected decision ' + result.decision);
  if (url !== 'https://api.vulnify.io/v1/events') throw new Error('unexpected url ' + url);
  console.log('CJS require ok', url);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
`,
  );

  writeFileSync(
    join(dir, 'esm.mjs'),
    `import { Vulnify } from '@vulnify/sdk';
if (typeof Vulnify !== 'function') throw new Error('ESM import did not export Vulnify');
let url;
global.fetch = async (input) => {
  url = String(input);
  return { ok: true, status: 200, json: async () => (${JSON.stringify(decision)}) };
};
const result = await new Vulnify({ apiKey: 'k', retries: 0 }).check({ action: 'READ_DATA' });
if (result.decision !== 'ALLOW') throw new Error('unexpected decision ' + result.decision);
if (url !== 'https://api.vulnify.io/v1/events') throw new Error('unexpected url ' + url);
console.log('ESM import ok', url);
`,
  );

  execFileSync(process.execPath, ['cjs.cjs'], { cwd: dir, stdio: 'inherit' });
  execFileSync(process.execPath, ['esm.mjs'], { cwd: dir, stdio: 'inherit' });
} finally {
  rmSync(dir, { recursive: true, force: true });
  rmSync(tarball, { force: true });
}

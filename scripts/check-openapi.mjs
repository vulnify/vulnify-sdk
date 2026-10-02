import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

// CI checks the committed spec, not https://api.vulnify.io/openapi.json.
// A live fetch would fail the build when the API is down or a deploy changes
// the contract under an unrelated pull request. Refresh the snapshot on purpose:
// replace spec/openapi.json, run `npm run generate:api`, and commit both files.
const bin = join('node_modules', '.bin', 'openapi-typescript');
const result = spawnSync(bin, ['spec/openapi.json', '-o', 'src/generated/openapi.ts', '--check'], {
  stdio: 'inherit',
});

if (result.status !== 0) {
  console.error('src/generated/openapi.ts drifted from spec/openapi.json. Run npm run generate:api and commit the result.');
  process.exit(result.status ?? 1);
}

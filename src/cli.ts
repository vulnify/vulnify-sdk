import { run } from './cli/run';

run(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    const message = err instanceof Error ? err.message : 'vulnify failed';
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  },
);

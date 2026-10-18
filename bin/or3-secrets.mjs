#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const child = spawn(
  'bun',
  [
    '--no-env-file',
    fileURLToPath(new URL('../dist/cli.js', import.meta.url)),
    ...process.argv.slice(2),
  ],
  { stdio: 'inherit' },
);
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
child.on('error', () => {
  process.stderr.write('or3-secrets requires the qualified Bun 1.3.14 runtime on PATH.\n');
  process.exitCode = 1;
});
child.on('exit', (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0);
});

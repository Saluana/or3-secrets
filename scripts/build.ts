import { mkdirSync, rmSync } from 'node:fs';
rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });
for (const [target, entrypoints] of [
  ['bun', ['src/cli.ts']],
  ['node', ['src/client.ts', 'src/module.ts']],
] as const) {
  const result = await Bun.build({
    entrypoints: [...entrypoints],
    outdir: 'dist',
    root: 'src',
    target,
    format: 'esm',
    minify: false,
    sourcemap: 'external',
    external: ['node:*', 'bun:*', '@nuxt/kit', 'nitropack/runtime/plugin', '#imports', '~~/*'],
  });
  if (!result.success) {
    for (const log of result.logs) process.stderr.write(String(log) + '\n');
    process.exit(1);
  }
}

// Keep Nitro's virtual imports at the plugin boundary; do not pass a bundled
// hundreds-line client through Nuxt's auto-import source transformation.
const plugin = await Bun.build({
  entrypoints: ['src/runtime/plugin.ts'],
  outdir: 'dist',
  root: 'src',
  target: 'node',
  format: 'esm',
  // External imports keep this plugin unbundled without an unsupported build option.
  external: ['nitropack/runtime/plugin', '#imports', '~~/*', '../client.js'],
});
if (!plugin.success) {
  for (const log of plugin.logs) process.stderr.write(String(log) + '\n');
  process.exit(1);
}

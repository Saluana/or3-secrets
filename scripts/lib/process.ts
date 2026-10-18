import type { ChildProcess } from 'node:child_process';
import { dirname } from 'node:path';

/** Stop disposable children without leaving a hung qualifier or an orphan service. */
export async function stopChild(
  child?: ChildProcess,
  options: { signal?: NodeJS.Signals; group?: boolean; requireGraceful?: boolean } = {},
): Promise<void> {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const send = (signal: NodeJS.Signals) => {
    if (options.group) process.kill(-child.pid!, signal);
    else child.kill(signal);
  };
  await new Promise<void>((resolve, reject) => {
    const killTimer = setTimeout(() => {
      try {
        send('SIGKILL');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ESRCH') finish(error as Error);
      }
    }, 5000);
    const deadline = setTimeout(() => finish(new Error('Child did not exit after SIGKILL')), 10000);
    const closed = () =>
      finish(
        options.requireGraceful && child.exitCode !== 0
          ? new Error('Service did not stop gracefully')
          : undefined,
      );
    const finish = (error?: Error) => {
      clearTimeout(killTimer);
      clearTimeout(deadline);
      child.removeListener('close', closed);
      if (error) reject(error);
      else resolve();
    };
    child.once('close', closed);
    try {
      send(options.signal ?? 'SIGTERM');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') finish();
      else finish(error as Error);
    }
  });
}

/** Exclude host/application configuration when qualifying a disposable deployment. */
export function cleanApplicationEnv(input: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env = { ...input };
  for (const key of Object.keys(env)) {
    if (
      /^(OR3_|NUXT_|NITRO_|VITE_|AUTH_|SSR_|CLERK_|CONVEX_|OPENROUTER_)/.test(key) ||
      ['NODE_OPTIONS', 'DOTENV_CONFIG_PATH', 'PORT', 'HOST'].includes(key)
    )
      delete env[key];
  }
  return {
    ...env,
    PATH: `${dirname(process.execPath)}:${input.PATH ?? ''}`,
    NUXT_TELEMETRY_DISABLED: '1',
  };
}

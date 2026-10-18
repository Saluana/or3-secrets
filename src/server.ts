import { chmodSync, chownSync, lstatSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';
import { Vault } from './store.js';
import { absent, safeParents } from './files.js';
import { MAX_BODY, OPERATIONS, SecretError, fail, parseInput, type Operation } from './protocol.js';

function errorResponse(code: string, status: number, vaultId?: string): Response {
  return Response.json({ error: { code } }, { status, headers: { 'cache-control': 'no-store', ...(vaultId ? { 'x-or3-vault-id': vaultId } : {}) } });
}
async function body(request: Request): Promise<unknown> {
  const length = request.headers.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_BODY)) fail('too_large', 413);
  if (!request.body) fail('invalid_request');
  const reader = request.body.getReader();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new SecretError('request_timeout', 408)), 5000); });
  const parts: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const next = await Promise.race([reader.read(), timeout]);
      if (next.done) break;
      size += next.value.byteLength; if (size > MAX_BODY) fail('too_large', 413); parts.push(next.value);
    }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts))); }
    catch { fail('invalid_request'); }
  } finally { clearTimeout(timer); void reader.cancel().catch(() => {}); }
}
export function serve(options: { vaultDir: string; keyFile: string; socketPath: string; socketGroup?: number }) {
  const vault = Vault.open(options.vaultDir, options.keyFile);
  let server: ReturnType<typeof Bun.serve> | undefined;
  let socketIdentity: { ino: number; dev: number } | undefined;
  let closing = false, inFlight = 0;
  const counters = { unauthorized: 0, invalid: 0, overload: 0, unavailable: 0 };
  let droppedIntervals = 0;
  const telemetry = setInterval(() => {
    if (Object.values(counters).some(count => count > 0)) {
      if (process.stderr.writableLength > 4096) { droppedIntervals = Math.min(2147483647, droppedIntervals + 1); return; }
      process.stderr.write(JSON.stringify({ droppedIntervals, code: 'request_rejections', intervalSeconds: 30, aggregation: 'coalesced_saturating_32bit', ...counters }) + '\n');
      droppedIntervals = 0;
      for (const key of Object.keys(counters) as (keyof typeof counters)[]) counters[key] = 0;
    }
  }, 30000); telemetry.unref();
  async function close() {
    if (closing) return; closing = true;
    clearInterval(telemetry);
    await server?.stop(false);
    vault.close();
    try { const current = lstatSync(options.socketPath); if (socketIdentity && current.ino === socketIdentity.ino && current.dev === socketIdentity.dev) unlinkSync(options.socketPath); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') process.exitCode = 1; }
  }
  try {
    safeParents(dirname(options.socketPath));
    const dir = lstatSync(dirname(options.socketPath)), group = options.socketGroup;
    if (dir.uid !== process.getuid!() || (dir.mode & 0o777) !== (group === undefined ? 0o700 : 0o750) || (group !== undefined && dir.gid !== group)) fail('unsafe_socket');
    absent(options.socketPath);
    server = Bun.serve({
      unix: options.socketPath,
      maxRequestBodySize: MAX_BODY,
      async fetch(request) {
        if (closing) return errorResponse('unavailable', 503, vault.vaultId);
        if (inFlight >= 16) { counters.overload = Math.min(2147483647, counters.overload + 1); return errorResponse('busy', 429, vault.vaultId); }
        inFlight++;
        try {
          if (request.headers.has('origin') || request.headers.has('cookie')) fail('forbidden', 403);
          if (request.method !== 'POST') fail('method_not_allowed', 405);
          if (request.headers.get('content-type')?.toLowerCase() !== 'application/json') fail('unsupported_media_type', 415);
          const url = new URL(request.url), operation = url.pathname.slice(4) as Operation;
          if (!url.pathname.startsWith('/v1/') || url.search || !OPERATIONS.includes(operation)) fail('not_found', 404);
          const authorization = request.headers.get('authorization');
          if (!authorization?.startsWith('Bearer ') || authorization.length > 256) fail('unauthorized', 401);
          const expectedVault = request.headers.get('x-or3-vault-id');
          if (!expectedVault || !/^[a-f0-9]{32}$/.test(expectedVault)) fail('invalid_request');
          const input = parseInput(operation, await body(request));
          const result = vault.perform(operation, input, authorization.slice(7), expectedVault);
          return Response.json(result, { headers: { 'cache-control': 'no-store', 'x-or3-vault-id': vault.vaultId } });
        } catch (error) {
          const safe = error instanceof SecretError ? error : new SecretError('unavailable', 503);
          const key = safe.status === 401 ? 'unauthorized' : safe.status === 429 ? 'overload' : safe.status >= 500 ? 'unavailable' : 'invalid';
          counters[key] = Math.min(2147483647, counters[key] + 1);
          if (vault.isFailed()) { process.exitCode = 1; setTimeout(() => { void close(); }, 50).unref(); }
          return errorResponse(safe.code, safe.status, vault.vaultId);
        } finally { inFlight--; }
      },
      error() { return errorResponse('unavailable', 503, vault.vaultId); },
    });
    const socket = lstatSync(options.socketPath); socketIdentity = { ino: socket.ino, dev: socket.dev };
    if (group !== undefined) chownSync(options.socketPath, process.getuid!(), group);
    chmodSync(options.socketPath, group === undefined ? 0o600 : 0o660);
    // A terminal signals both the Node launcher and this process; the launcher
    // also forwards it. Keep handlers installed while the idempotent close drains.
    process.on('SIGTERM', () => { void close(); }); process.on('SIGINT', () => { void close(); });
    return { vaultId: vault.vaultId, close };
  } catch (error) { clearInterval(telemetry); void close(); throw error; }
}

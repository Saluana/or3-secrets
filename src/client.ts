import { request } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readCredential, validateSocket } from './files.js';
import { MAX_BODY, SecretError, identifier, parseContext, parseInput, parseResponse, fail, type Context, type Cursor, type Operation, type SecretStore, type TokenPolicy } from './protocol.js';
export type { Scope, Context, SecretRef, SecretMeta, SecretStore, TokenPolicy, Cursor, Receipt } from './protocol.js';
export { SecretError } from './protocol.js';

export type ClientOptions = Readonly<{ socketPath: string; tokenFile: string; vaultId: string; timeoutMs?: number; signal?: AbortSignal }>;
export function createClient(options: ClientOptions) {
  if (options.timeoutMs !== undefined && (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 60000)) fail('invalid_configuration');
  if (!/^[a-f0-9]{32}$/.test(options.vaultId) || !options.socketPath.startsWith('/') || !options.tokenFile.startsWith('/')) fail('invalid_configuration');
  const call = <T>(operation: Operation, input: Record<string, unknown>, context?: Partial<Context>): Promise<T> => {
    const requestContext = parseContext({ requestId: randomUUID(), ...context });
    const wire = { ...input, context: requestContext };
    parseInput(operation, wire);
    const bytes = Buffer.from(JSON.stringify(wire));
    if (bytes.length > MAX_BODY) fail('too_large', 413);
    let token: string;
    try { validateSocket(options.socketPath); token = readCredential(options.tokenFile); }
    catch (error) { if (error instanceof SecretError) throw error; fail('unavailable', 503); }
    return new Promise<T>((yes, no) => {
      let settled = false;
      const finish = (error?: SecretError, value?: T) => { if (settled) return; settled = true; clearTimeout(timer); if (error) no(error); else yes(value!); };
      const req = request({ socketPath: options.socketPath, path: `/v1/${operation}`, method: 'POST', agent: false, signal: options.signal, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'content-length': String(bytes.length), 'x-or3-vault-id': options.vaultId } }, response => {
        const chunks: Buffer[] = []; let length = 0;
        response.on('data', (chunk: Buffer) => { length += chunk.length; if (length > MAX_BODY) { finish(new SecretError('invalid_response', 503)); req.destroy(); } else chunks.push(chunk); });
        response.on('error', () => finish(new SecretError('unavailable', 503)));
        response.on('end', () => {
          if (settled) return;
          if (response.headers['x-or3-vault-id'] !== options.vaultId) { finish(new SecretError('vault_mismatch', 409)); return; }
          try {
            const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
            if (response.statusCode !== 200) {
              // The service's error code is constrained; never echo a response body/message.
              const code = data?.error?.code;
              finish(new SecretError(typeof code === 'string' && /^[a-z_]{1,64}$/.test(code) ? code : 'unavailable', response.statusCode ?? 503));
            } else finish(undefined, parseResponse(operation, data) as T);
          } catch { finish(new SecretError('invalid_response', 503)); }
        });
      });
      const timer = setTimeout(() => { finish(new SecretError('request_timeout', 503)); req.destroy(); }, options.timeoutMs ?? 10000);
      req.on('error', () => finish(new SecretError(options.signal?.aborted ? 'request_aborted' : 'unavailable', 503))); req.end(bytes);
    });
  };
  const store: SecretStore = {
    inspect: (input, context) => call('secrets/inspect', input, context),
    list: (input, context) => call('secrets/list', input, context),
    put: (input, context) => call('secrets/put', input, context),
    resolve: (input, context) => call('secrets/resolve', input, context),
    delete: (input, context) => call('secrets/delete', input, context),
  };
  return {
    ...store,
    status: (context?: Partial<Context>) => call<{ vaultId: string; protocolVersion: number; expiresAt: number | null; auditSeq: number; storage: Record<string, number | string> }>('status', {}, context),
    issueToken: (policy: TokenPolicy, context?: Partial<Context>) => call<{ token: string; meta: { id: string } }>('tokens/issue', policy, context),
    listTokens: (input: { after?: string; limit?: number } = {}, context?: Partial<Context>) => call<{ items: unknown[]; next?: string }>('tokens/list', input, context),
    revokeToken: (id: string, context?: Partial<Context>) => call<unknown>('tokens/revoke', { id: identifier(id) }, context),
    readAudit: (input: { after: Cursor | null; through?: Cursor; limit: number }, context?: Partial<Context>) => call<{ events: { seq: number; previousMac: string; event: Record<string, unknown>; mac: string }[]; cursor: Cursor | null; through: Cursor }>('audit/read', input, context),
  };
}

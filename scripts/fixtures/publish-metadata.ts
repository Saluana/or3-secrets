// External metadata responses for disposable npm lifecycle E2E only. No publication is attempted.
import { execFileSync } from 'node:child_process';

const originalFetch = globalThis.fetch;
globalThis.fetch = (async (input, options) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (url.hostname === 'registry.npmjs.org' && url.pathname.startsWith('/@or3%2fsecrets/')) {
    if (process.env.OR3_PUBLISH_FIXTURE_MODE === 'offline')
      throw new Error('fixture-registry-offline');
    return process.env.OR3_PUBLISH_FIXTURE_MODE === 'published'
      ? Response.json({ version: '0.1.0' })
      : Response.json('Not Found', { status: 404 });
  }
  if (url.hostname === 'api.github.com' && url.pathname.endsWith('/qualify.yml/runs')) {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    return Response.json({
      workflow_runs:
        process.env.OR3_PUBLISH_FIXTURE_MODE === 'unqualified'
          ? []
          : [{ head_sha: head, event: 'push', conclusion: 'success' }],
    });
  }
  return originalFetch(input, options);
}) as typeof fetch;

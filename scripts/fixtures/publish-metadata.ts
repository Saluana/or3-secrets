// Registry metadata responses for disposable npm lifecycle E2E only. No publication is attempted.
const originalFetch = globalThis.fetch;
globalThis.fetch = (async (input, options) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (url.hostname === 'registry.npmjs.org' && url.pathname.startsWith('/@or3%2fsecrets/')) {
    if (process.env.OR3_PUBLISH_FIXTURE_MODE === 'offline')
      throw new Error('fixture-registry-offline');
    return process.env.OR3_PUBLISH_FIXTURE_MODE === 'published'
      ? Response.json({ version: url.pathname.split('/').at(-1) })
      : Response.json(`version not found: ${url.pathname.split('/').at(-1)}`, { status: 404 });
  }
  return originalFetch(input, options);
}) as typeof fetch;

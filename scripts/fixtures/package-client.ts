import { strict as assert } from 'node:assert';
import { pathToFileURL } from 'node:url';

const [modulePath, options] = process.argv.slice(2);
assert.ok(modulePath, 'Packaged client path is required');
const packaged: typeof import('../../src/client') = await import(pathToFileURL(modulePath).href);
assert.equal(typeof packaged.createClient, 'function');
if (options) {
  const client = packaged.createClient(JSON.parse(options));
  const scope = { namespace: 'package', ownerUserId: 'u', workspaceId: 'w', consumerId: 'p' };
  const meta = await client.put({
    scope,
    name: 'packaged',
    value: 'synthetic-package-value',
    expectedRevision: 0,
  });
  const result = await client.resolve({ scope, selector: { ref: meta.ref } });
  assert.equal(result.value, 'synthetic-package-value');
}

import { request } from 'node:http';
import { strict as assert } from 'node:assert';

const [socketPath, expectedOutage] = process.argv.slice(2);
assert.ok(socketPath, 'Provider socket path is required');
const probe = request({ socketPath, path: '/api/probe' }, (response) => {
  let body = '';
  response.setEncoding('utf8');
  response.on('data', (chunk) => {
    body += chunk;
  });
  response.on('end', () => {
    const result = JSON.parse(body);
    if (expectedOutage === 'true') {
      assert.equal(response.statusCode, 503);
      assert.equal(result.data?.code, 'unavailable');
    } else {
      assert.equal(response.statusCode, 200);
      assert.equal(result.ok, true);
    }
  });
});
probe.on('error', () => {
  process.exitCode = 3;
});
probe.end();

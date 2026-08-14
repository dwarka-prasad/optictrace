// Smoke test: Express app + OpticTrace middleware. Verifies engine parity
// (restriction, redaction incl. `**` descent, labels) and — when
// OPTIC_AGENT_URL is set — real ingestion into a running agent.
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const optictrace = require('..');
const { Engine, redactPath, matchSegments, splitPath, REDACTED } = require('../engine');

const CONFIG = `
version: 1
service:
  name: express-test
rules:
  - name: no-capture-on-auth
    match: { path: "/auth/**" }
    restrict: [request_body, response_body, headers]
  - name: redact-payments
    match: { path: "/payments/**" }
    redact:
      headers: [Authorization]
      json_fields: ["$.**.card.number"]
    labels:
      tenant: "header:X-Tenant-ID"
`;

// --- unit checks: engine parity with Go -------------------------------------
assert.ok(matchSegments(splitPath('/api/v1/**'), splitPath('/api/v1/a/b')));
assert.ok(!matchSegments(splitPath('/api/*'), splitPath('/api/a/b')));
assert.deepStrictEqual(
  redactPath({ echo: { card: { number: '4111' } }, card: { number: '2222' } }, ['**', 'card', 'number']),
  { echo: { card: { number: REDACTED } }, card: { number: REDACTED } },
);
const eng = new Engine(require('js-yaml').load(CONFIG));
const p = eng.evaluate('POST', '/auth/login');
assert.strictEqual(p.captureRequestBody, false);
assert.strictEqual(p.captureHeaders, false);
console.log('✓ engine unit checks passed');

// --- integration: full middleware over HTTP ---------------------------------
async function main() {
  const cfgFile = path.join(os.tmpdir(), `optic-express-${process.pid}.yaml`);
  fs.writeFileSync(cfgFile, CONFIG);

  const emitted = [];
  const agentUrl = process.env.OPTIC_AGENT_URL;

  const app = express();
  // Capture stdout records for assertions while still exercising ingest.
  const origWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (line, ...rest) => {
    if (String(line).includes('http_exchange')) {
      emitted.push(JSON.parse(String(line)));
      return true;
    }
    return origWrite(line, ...rest);
  };

  app.use(optictrace({ configPath: cfgFile, agentUrl, consoleLog: true }));
  app.use(express.json());
  app.post('/payments/charge', (req, res) => res.status(201).json({ ok: true, echo: req.body }));
  app.post('/auth/login', (_req, res) => res.json({ token: 'secret-token' }));

  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  const r1 = await fetch(`${base}/payments/charge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer tok', 'X-Tenant-ID': 'acme' },
    body: JSON.stringify({ card: { number: '4111111111111111' }, amount: 5 }),
  });
  assert.strictEqual(r1.status, 201);
  const body1 = await r1.json();
  assert.strictEqual(body1.echo.card.number, '4111111111111111', 'traffic must not be mutated');

  await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'hunter2' }),
  });

  await new Promise((r) => setTimeout(r, 300));
  process.stdout.write = origWrite;
  server.close();

  const pay = emitted.find((e) => e.path === '/payments/charge');
  const auth = emitted.find((e) => e.path === '/auth/login');
  assert.ok(pay && auth, 'both records emitted');

  const payStr = JSON.stringify(pay);
  assert.ok(!payStr.includes('4111111111111111'), 'card number leaked into telemetry');
  assert.ok(payStr.includes(REDACTED), 'redaction placeholder missing');
  assert.strictEqual(pay.request_headers.authorization, REDACTED);
  assert.strictEqual(pay.labels.tenant, 'acme');
  assert.strictEqual(pay.matched_rules[0], 'redact-payments');

  const authStr = JSON.stringify(auth);
  assert.ok(!authStr.includes('hunter2'), 'restricted request body leaked');
  assert.ok(!authStr.includes('secret-token'), 'restricted response body leaked');
  assert.ok(!auth.request_headers, 'restricted headers leaked');
  assert.strictEqual(auth.status, 200);

  console.log('✓ middleware integration checks passed');
  if (agentUrl) console.log(`✓ records shipped to agent at ${agentUrl}`);
  fs.unlinkSync(cfgFile);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

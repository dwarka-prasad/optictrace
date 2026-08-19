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
      query_params: [api_key]
      json_fields: ["$.**.card.number"]
    labels:
      tenant: "header:X-Tenant-ID"
      region: "header:X-Region|^([a-z]{2})-"
      channel: "static:direct"
      area: "path:1"
      partner: "json:$.**.source"
      outcome: "json_response:$.status"
  - name: meter-ai
    match: { path: "/ai/**" }
    restrict: [response_body]
    meter:
      tokens: "$.usage.total_tokens"
`;

// --- unit checks: engine parity with Go -------------------------------------
assert.ok(matchSegments(splitPath('/api/v1/**'), splitPath('/api/v1/a/b')));
assert.ok(!matchSegments(splitPath('/api/*'), splitPath('/api/a/b')));
assert.deepStrictEqual(
  redactPath({ echo: { card: { number: '4111' } }, card: { number: '2222' } }, ['**', 'card', 'number']),
  { echo: { card: { number: REDACTED } }, card: { number: REDACTED } },
);
// --- tail-based sampling parity --------------------------------------------
{
  const { keepBody, tailSampled } = require('../engine');
  const tailCfg = require('js-yaml').load(`
version: 1
service: { name: t }
rules:
  - name: hot
    match: { path: "/hot/**" }
    sample: 0.0001
    keep_errors: true
    keep_slower_than: 10ms
`);
  const hot = new Engine(tailCfg).evaluate('GET', '/hot/reads');
  assert.ok(tailSampled(hot), 'tail rules must force buffering');
  assert.ok(!keepBody(hot, false, 200, 1), 'an unsampled fast 200 must keep no body');
  assert.ok(keepBody(hot, false, 500, 1), 'keep_errors must rescue a 5xx');
  // keep_errors means 5xx. A 404 is usually the client's problem, and rescuing
  // it would defeat the sampling it works alongside.
  assert.ok(!keepBody(hot, false, 404, 1), 'keep_errors must NOT rescue a 4xx');
  assert.ok(keepBody(hot, false, 200, 25), 'keep_slower_than must rescue a slow request');
  assert.ok(keepBody(hot, true, 200, 1), 'a drawn request always keeps its body');
  assert.strictEqual(hot.keepSlowerThanMs, 10, 'go-style duration not parsed');
}

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

  let seenSpan = null;
  app.post('/payments/charge', (req, res) => {
    // What a handler would do to propagate the trace to a downstream call.
    seenSpan = optictrace.currentSpan()?.spanId ?? null;
    res.status(201).json({ status: 'captured', echo: req.body });
  });
  app.post('/auth/login', (_req, res) => res.json({ token: 'secret-token' }));
  app.post('/ai/complete', (_req, res) =>
    res.json({ completion: 'hi', usage: { prompt_tokens: 86, total_tokens: 128 } }));

  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  const r1 = await fetch(`${base}/payments/charge?api_key=live_sk_1&page=2`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer tok',
      'X-Tenant-ID': 'acme',
      'X-Region': 'ap-south-1',
    },
    body: JSON.stringify({ source: 'flipkart', card: { number: '4111111111111111' }, amount: 5 }),
  });
  assert.strictEqual(r1.status, 201);
  const body1 = await r1.json();
  assert.strictEqual(body1.echo.card.number, '4111111111111111', 'traffic must not be mutated');

  await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'hunter2' }),
  });

  await fetch(`${base}/ai/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt: 'hi' }),
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

  // --- parity with the Go engine, added because these were all missing ----
  assert.ok(pay.trace_id && pay.trace_id.length === 32, 'no trace id on the record');
  assert.ok(pay.span_id && pay.span_id.length === 16, 'no span id on the record');
  assert.notStrictEqual(pay.trace_id, auth.trace_id, 'separate requests share a trace id');

  assert.strictEqual(pay.labels.region, 'ap', 'regex capture label');
  assert.strictEqual(pay.labels.channel, 'direct', 'static label');
  assert.strictEqual(pay.labels.area, 'payments', 'path label is 1-based');
  assert.strictEqual(pay.labels.partner, 'flipkart', 'label read from the request payload');
  assert.strictEqual(pay.labels.outcome, 'captured', 'label read from the response');
  assert.ok(
    !JSON.stringify(pay.labels).includes('4111111111111111'),
    'a label must never carry a value the policy masked',
  );

  assert.ok(pay.query && pay.query.includes(`api_key=${REDACTED}`), 'query credential not masked');
  assert.ok(pay.query.includes('page=2'), 'unnamed query params must survive');

  const ai = emitted.find((e) => e.path === '/ai/complete');
  assert.ok(ai, 'metered record emitted');
  assert.strictEqual(ai.meters?.tokens, 128, 'meters not extracted');
  assert.ok(!ai.response_body, 'restricted response body was stored');

  // Trace context must be visible to the handler, which is what makes an
  // outbound call nest under this request instead of starting a new tree.
  assert.ok(seenSpan && seenSpan === pay.span_id, 'handler could not see its own span');

  console.log('✓ middleware integration checks passed');

  // Delivery. Offline checks cannot tell you whether a real agent ACCEPTS what
  // this SDK produces — the Python SDK passed all of its own tests while a
  // live agent rejected 100% of its records.
  if (agentUrl) {
    const logs = new optictrace.LogShipper(agentUrl, 'express-test');
    logs.info('express selftest line');
    logs.warn('careless debug: Bearer topsecret123');
    await logs.close();
    assert.strictEqual(logs.failed, 0, `log delivery failed: ${logs.lastError}`);

    await new Promise((r) => setTimeout(r, 1200));
    const stored = await (await fetch(`${agentUrl}/api/logs?window=5m&limit=50`)).text();
    assert.ok(stored.includes('"source":"express"'), 'a live agent did not accept a record');
    console.log(`✓ a live agent accepted records and ${logs.sent} log line(s) from this SDK`);
  }
  fs.unlinkSync(cfgFile);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

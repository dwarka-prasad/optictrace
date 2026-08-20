'use strict';

/**
 * W3C trace context for the Express middleware.
 *
 * Correlation must be a fact, not a guess. The span generated here goes onto
 * the record AND into an AsyncLocalStorage, so a log line or an outbound call
 * can name the exact request it belongs to. Matching on timestamps would,
 * under concurrent traffic, file one tenant's data inside another's request.
 */

const { AsyncLocalStorage } = require('node:async_hooks');
const crypto = require('node:crypto');

const HEADER = 'traceparent';
const TRACEPARENT = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;

// AsyncLocalStorage, not a module-level variable: Node serves requests
// concurrently, and a global would hand one request's span to another.
const storage = new AsyncLocalStorage();

const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');

/**
 * Adopt an inbound traceparent, or start a fresh trace. A malformed header
 * starts a new trace rather than failing anything: losing correlation is a
 * nuisance, failing a request over a bad header would be a fault.
 */
function fromHeader(raw) {
  const m = TRACEPARENT.exec(String(raw ?? '').trim());
  if (m) {
    const [, version, traceId, parent, flags] = m;
    const usable =
      version !== 'ff' && traceId !== '0'.repeat(32) && parent !== '0'.repeat(16);
    if (usable) {
      return {
        traceId,
        spanId: hex(8),
        parentSpanId: parent,
        sampled: (parseInt(flags, 16) & 1) === 1,
      };
    }
  }
  return { traceId: hex(16), spanId: hex(8), parentSpanId: '', sampled: true };
}

const header = (ctx) =>
  `00-${ctx.traceId}-${ctx.spanId}-${ctx.sampled ? '01' : '00'}`;

/** Run `fn` with `ctx` as the current span. */
const run = (ctx, fn) => storage.run(ctx, fn);

/** The span currently being served, or undefined outside a request. */
const current = () => storage.getStore();

/**
 * Headers for a call this service makes downstream, so the next hop nests
 * under this one. Carries THIS hop's span — forwarding the inbound header
 * unchanged would make every downstream call a sibling and flatten the tree.
 */
function outboundHeaders(extra = {}) {
  const ctx = current();
  return ctx ? { ...extra, [HEADER]: header(ctx) } : { ...extra };
}

/** A random id of the given HEX LENGTH — 16 for a span, 32 for a trace.
 *  Exposed because inner spans need ids of the same shape, and a second
 *  generator would be a second place for the convention to drift. */
const randomHex = (hexChars) => hex(hexChars / 2);

module.exports = { HEADER, fromHeader, header, run, current, outboundHeaders, randomHex };

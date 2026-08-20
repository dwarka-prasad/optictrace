'use strict';

const trace = require('./trace');
const { LogShipper } = require('./logs');

/**
 * Inner spans: the operations that run while a request is being served.
 *
 * The middleware records the HTTP exchange. This records what happened inside
 * it — a query, a cache lookup, an outbound call — which is the difference
 * between "this request took 300ms" and "this request took 300ms, 280 of them
 * in one query".
 *
 * Attributes are governed by the agent before storage, so a statement that
 * quotes its parameters is redacted before anything is written. Pass the
 * statement TEMPLATE where you can: the safest secret is the one never sent.
 */

/**
 * The innermost open span, so operations nest: a query inside a transaction
 * parents to the transaction rather than jumping to the request.
 *
 * AsyncLocalStorage rather than a module-level variable, because Node
 * interleaves requests on one thread and a shared variable would parent one
 * request's query to another request's transaction.
 */
const { AsyncLocalStorage } = require('node:async_hooks');
const openSpan = new AsyncLocalStorage();

class SpanRecorder {
  /**
   * @param {string} agentUrl  the agent's base URL. Empty makes every span
   *                           inert, so instrumentation can stay in place in
   *                           an environment with no agent rather than being
   *                           guarded by an `if` at every call site.
   * @param {string} service
   * @param {object} [opts]    maxQueue, flushMs, batchSize — see LogShipper
   */
  constructor(agentUrl, service, opts = {}) {
    // The shipper is the app-log one pointed at a different path: batching,
    // bounded queue and delivery counters are the same problem, and a second
    // copy would drift from this one.
    this.shipper = agentUrl
      ? new LogShipper(agentUrl, service, { ...opts, path: '/api/spans/ingest' })
      : null;
    this.service = service;
  }

  /**
   * Opens a span. `kind` classifies it for the waterfall and the breakdown:
   * db, cache, http, queue, rpc, internal.
   *
   * Nesting: pass `{ parent: outer.spanId }`, or use `observe()`, which
   * establishes the scope for you. See the note in the constructor for why
   * this SDK needs that and the others do not.
   *
   * Outside a request the span has no parent and the agent drops it by
   * default — work belonging to no request cannot be attributed to one.
   */
  start(name, kind, opts = {}) {
    return new InnerSpan(this, name, kind, opts);
  }

  /**
   * Runs fn as a span, which is the shape most call sites want: no try/finally
   * to forget, and the error is recorded automatically.
   *
   *   const rows = await spans.observe('db.query', 'db', (sp) => {
   *     sp.set('db.statement', SQL);
   *     return pool.query(SQL, [id]);
   *   });
   */
  async observe(name, kind, fn) {
    const sp = this.start(name, kind);
    try {
      return await openSpan.run(sp.spanId, () => fn(sp));
    } catch (e) {
      sp.fail(e);
      throw e;
    } finally {
      sp.end();
    }
  }

  /** Delivery counters, so "are my spans arriving?" has an answer. */
  get sent() {
    return this.shipper ? this.shipper.sent : 0;
  }
  get failed() {
    return this.shipper ? this.shipper.failed : 0;
  }
  get dropped() {
    return this.shipper ? this.shipper.dropped : 0;
  }

  async close() {
    if (this.shipper) await this.shipper.close();
  }
}

class InnerSpan {
  constructor(owner, name, kind, opts = {}) {
    this.owner = owner;
    this.name = name;
    this.kind = kind || '';
    this.startedAt = new Date();
    this.startHr = process.hrtime.bigint();
    this.attrs = {};
    this.failure = null;
    this.ended = false;

    const ctx = trace.current();
    this.traceId = ctx?.traceId ?? '';
    this.spanId = trace.randomHex(16);
    // Node has no way to leave an AsyncLocalStorage scope imperatively, so
    // `start()` on its own cannot establish one for whatever runs next. Use
    // `observe()`, which does, or pass an explicit parent — the other SDKs
    // nest from `start()` because their languages let a scope be popped.
    this.parentSpanId = opts.parent ?? openSpan.getStore() ?? ctx?.spanId ?? '';
  }

  /**
   * Attaches an attribute. Conventional keys — db.statement, db.rows,
   * cache.key, cache.hit, http.method, http.url, http.status — are what the
   * dashboard reads.
   */
  set(key, value) {
    if (key != null && value != null) this.attrs[key] = String(value);
    return this;
  }

  /**
   * Marks the operation as failed. A falsy error is a no-op.
   *
   * A failed operation survives the agent's min_duration filter: "it returned
   * in 200µs" and "it returned in 200µs with an error" are not the same event,
   * and the second is the one someone is looking for.
   */
  fail(err) {
    if (err) this.failure = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    return this;
  }

  /**
   * Ends the span and queues it. Idempotent: a finally-block end alongside an
   * explicit one is a natural thing to write and must not double count.
   */
  end() {
    if (this.ended) return;
    this.ended = true;
    if (!this.owner.shipper) return;

    const ms = Number(process.hrtime.bigint() - this.startHr) / 1e6;
    const span = {
      start: this.startedAt.toISOString(),
      service: this.owner.service,
      trace_id: this.traceId,
      span_id: this.spanId,
      name: this.name,
      kind: this.kind,
      duration_ms: ms,
      source: 'express',
    };
    if (this.parentSpanId) span.parent_span_id = this.parentSpanId;
    if (this.failure) span.error = this.failure;
    if (Object.keys(this.attrs).length) span.attrs = this.attrs;
    this.owner.shipper.ship(span);
  }
}

module.exports = { SpanRecorder, InnerSpan };

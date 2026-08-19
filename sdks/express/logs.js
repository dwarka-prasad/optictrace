'use strict';

/**
 * Ships application log lines to OpticTrace, correlated to the span serving them.
 *
 *   const { LogShipper } = require('@optictrace/express');
 *   const logs = new LogShipper('http://localhost:9095', 'checkout');
 *   logs.info('order received', { sku: 'SKU-100' });
 *
 * The span comes from the middleware's AsyncLocalStorage, so nothing at the
 * call site needs to know about OpticTrace. Lines emitted with no request in
 * flight carry no span; the agent decides what happens to them, and by default
 * drops and counts them rather than guessing an owner.
 */

const trace = require('./trace');

class LogShipper {
  /**
   * @param {string} agentUrl
   * @param {string} service
   * @param {object} [opts]
   * @param {number} [opts.maxQueue=10000]  bounded, so a logging storm costs a
   *                                        bounded amount of memory and then
   *                                        drops visibly rather than growing
   * @param {number} [opts.flushMs=500]
   * @param {number} [opts.batchSize=200]
   */
  constructor(agentUrl, service, opts = {}) {
    this.url = String(agentUrl).replace(/\/+$/, '') + '/api/applogs/ingest';
    this.service = service;
    this.maxQueue = opts.maxQueue ?? 10_000;
    this.batchSize = opts.batchSize ?? 200;
    this.queue = [];

    // Counters, not silence. This SDK's Python sibling swallowed every
    // delivery failure and shipped nothing at all for weeks while looking
    // perfectly healthy.
    this.sent = 0;
    this.failed = 0;
    this.dropped = 0;
    this.lastError = null;

    this.timer = setInterval(() => this.flush(), opts.flushMs ?? 500);
    if (this.timer.unref) this.timer.unref();   // never hold the process open
  }

  log(level, message, fields) {
    const ctx = trace.current();
    if (this.queue.length >= this.maxQueue) {
      this.dropped += 1;
      return;
    }
    this.queue.push({
      time: new Date().toISOString(),
      service: this.service,
      trace_id: ctx?.traceId ?? '',
      span_id: ctx?.spanId ?? '',
      level,
      message: String(message),
      fields: fields
        ? Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, String(v)]))
        : undefined,
      source: 'express',
    });
    if (this.queue.length >= this.batchSize) this.flush();
  }

  debug(m, f) { this.log('debug', m, f); }
  info(m, f) { this.log('info', m, f); }
  warn(m, f) { this.log('warn', m, f); }
  error(m, f) { this.log('error', m, f); }

  async flush() {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.queue.length);
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(batch),
      });
      if (!res.ok) {
        this.failed += batch.length;
        this.lastError = `HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`;
      } else {
        this.sent += batch.length;
      }
    } catch (e) {
      // Never throws into the application: telemetry must not fail a request.
      this.failed += batch.length;
      this.lastError = String(e);
    }
  }

  async close() {
    clearInterval(this.timer);
    await this.flush();
  }
}

module.exports = { LogShipper };

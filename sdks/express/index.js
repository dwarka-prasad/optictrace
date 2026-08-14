// OpticTrace middleware for Express.
//
//   const optictrace = require('@optictrace/express');
//   app.use(optictrace({ configPath: 'optic.yaml', agentUrl: 'http://localhost:9095' }));
//
// The middleware evaluates optic.yaml per request, applies restriction and
// redaction IN-PROCESS, and ships the governed record to the OpticTrace
// agent's /api/ingest (fire-and-forget — telemetry can never take down the
// app or add tail latency).
'use strict';

const fs = require('fs');
const yaml = require('js-yaml');
const { Engine, sanitizeHeaders, redactBody } = require('./engine');

/**
 * @param {object}  options
 * @param {string}  [options.configPath='optic.yaml']  path to optic.yaml
 * @param {string}  [options.agentUrl]                 OpticTrace agent base URL (e.g. http://localhost:9095); omit to log to console instead
 * @param {string}  [options.serviceName]              override service.name from the config
 * @param {boolean} [options.consoleLog=false]         also emit records as JSON lines on stdout
 * @param {function} [options.onError]                 called with transport errors (default: silent)
 * @returns {import('express').RequestHandler}
 */
function optictrace(options = {}) {
  const configPath = options.configPath ?? 'optic.yaml';
  const cfg = yaml.load(fs.readFileSync(configPath, 'utf8'));
  const engine = new Engine(cfg);
  const service = options.serviceName ?? engine.serviceName;
  const ingestUrl = options.agentUrl ? new URL('/api/ingest', options.agentUrl).toString() : null;
  const onError = options.onError ?? (() => {});

  // Hot reload on SIGHUP, mirroring the Go agent.
  process.on('SIGHUP', () => {
    try {
      const next = new Engine(yaml.load(fs.readFileSync(configPath, 'utf8')));
      engine.rules = next.rules;
      engine.defaults = next.defaults;
      engine.captureLimit = next.captureLimit;
    } catch (e) {
      onError(e);
    }
  });

  return function optictraceMiddleware(req, res, next) {
    const start = process.hrtime.bigint();
    const policy = engine.evaluate(req.method, req.path ?? req.url.split('?')[0]);
    const sampled = policy.sampleRate >= 1 || Math.random() < policy.sampleRate;

    // --- request body capture: tee the raw stream, never consume it ------
    let reqChunks = null;
    let reqBytes = 0;
    let reqTruncated = false;
    if (sampled && policy.captureRequestBody) {
      reqChunks = [];
      req.on('data', (chunk) => {
        reqBytes += chunk.length;
        const captured = reqChunks.reduce((n, c) => n + c.length, 0);
        if (captured < policy.captureLimit) {
          reqChunks.push(chunk.slice(0, policy.captureLimit - captured));
          if (chunk.length > policy.captureLimit - captured) reqTruncated = true;
        } else {
          reqTruncated = true;
        }
      });
    }

    // --- response body capture: wrap write/end ---------------------------
    let respChunks = null;
    let respBytes = 0;
    let respTruncated = false;
    const capture = (chunk) => {
      if (chunk == null) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      respBytes += buf.length;
      if (respChunks) {
        const captured = respChunks.reduce((n, c) => n + c.length, 0);
        if (captured < policy.captureLimit) {
          respChunks.push(buf.slice(0, policy.captureLimit - captured));
          if (buf.length > policy.captureLimit - captured) respTruncated = true;
        } else {
          respTruncated = true;
        }
      }
    };
    if (sampled && policy.captureResponseBody) respChunks = [];
    const origWrite = res.write.bind(res);
    const origEnd = res.end.bind(res);
    res.write = function (chunk, ...args) {
      capture(chunk);
      return origWrite(chunk, ...args);
    };
    res.end = function (chunk, ...args) {
      capture(chunk);
      return origEnd(chunk, ...args);
    };

    res.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
      const record = {
        time: new Date().toISOString(),
        service,
        method: req.method,
        path: req.path ?? req.url.split('?')[0],
        route: policy.routePattern || (req.route?.path ?? req.path),
        status: res.statusCode,
        duration_ms: durationMs,
        remote: req.ip ?? req.socket?.remoteAddress ?? '',
        source: 'express',
        req_bytes: reqBytes || Number(req.headers['content-length'] ?? 0),
        resp_bytes: respBytes,
        matched_rules: policy.matchedRules.length ? policy.matchedRules : undefined,
      };
      if (policy.captureHeaders) {
        record.request_headers = sanitizeHeaders(req.headers, policy);
        record.response_headers = sanitizeHeaders(res.getHeaders(), policy);
      }
      if (reqChunks && reqChunks.length) {
        record.request_body = redactBody(
          Buffer.concat(reqChunks).toString('utf8'),
          req.headers['content-type'],
          policy,
        );
        if (reqTruncated) record.req_truncated = true;
      }
      if (respChunks && respChunks.length) {
        record.response_body = redactBody(
          Buffer.concat(respChunks).toString('utf8'),
          String(res.getHeader('content-type') ?? ''),
          policy,
        );
        if (respTruncated) record.resp_truncated = true;
      }
      if (Object.keys(policy.labels).length) {
        record.labels = {};
        for (const [name, src] of Object.entries(policy.labels)) {
          const [kind, key] = String(src).split(':');
          record.labels[name] =
            kind === 'header'
              ? String(req.headers[key.toLowerCase()] ?? '')
              : kind === 'query'
                ? String(req.query?.[key] ?? '')
                : '';
        }
      }

      if (options.consoleLog || !ingestUrl) {
        process.stdout.write(JSON.stringify({ msg: 'http_exchange', ...record }) + '\n');
      }
      if (ingestUrl) {
        // Fire-and-forget; failures are reported via onError only.
        fetch(ingestUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(record),
          keepalive: true,
        }).catch(onError);
      }
    });

    next();
  };
}

module.exports = optictrace;
module.exports.optictrace = optictrace;

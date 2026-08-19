// OpticTrace rule engine — JavaScript port, semantics-identical to the Go
// engine (internal/engine). Governance runs IN-PROCESS: sensitive payloads
// are restricted/redacted before any byte leaves the application, and only
// the governed record is shipped to the OpticTrace agent.
'use strict';

const REDACTED = '[REDACTED]';

/** Split "/api/v1/x/" into ["api","v1","x"]. */
function splitPath(p) {
  const t = String(p ?? '').replace(/^\/+|\/+$/g, '');
  return t === '' ? [] : t.split('/');
}

/** Shell-style match for one path segment (*, ?, [ranges]). */
function segMatch(pattern, seg) {
  if (pattern === '*') return true;
  const re = new RegExp(
    '^' +
      pattern
        .replace(/[.+^${}()|\\]/g, '\\$&')
        .replace(/\*/g, '[^/]*')
        .replace(/\?/g, '[^/]') +
      '$',
  );
  return re.test(seg);
}

/** Segment-wise glob: `*` = one segment, `**` = zero or more segments. */
function matchSegments(pattern, segs) {
  if (pattern.length === 0) return segs.length === 0;
  if (pattern[0] === '**') {
    if (pattern.length === 1) return true;
    for (let i = 0; i <= segs.length; i++) {
      if (matchSegments(pattern.slice(1), segs.slice(i))) return true;
    }
    return false;
  }
  if (segs.length === 0) return false;
  if (!segMatch(pattern[0], segs[0])) return false;
  return matchSegments(pattern.slice(1), segs.slice(1));
}

class Engine {
  /** @param {object} cfg parsed optic.yaml */
  constructor(cfg) {
    if (!cfg || cfg.version !== 1) {
      throw new Error(`optic.yaml: unsupported version ${cfg && cfg.version} (expected 1)`);
    }
    this.serviceName = cfg.service?.name ?? '';
    const cap = cfg.defaults?.capture ?? {};
    this.defaults = {
      request_body: cap.request_body !== false,
      response_body: cap.response_body !== false,
      headers: cap.headers !== false,
    };
    this.captureLimit = cfg.defaults?.capture_limit_bytes ?? 65536;
    this.rules = (cfg.rules ?? []).map((r, i) => {
      if (!r.match?.path?.startsWith('/')) {
        throw new Error(`optic.yaml rule ${r.name ?? '#' + i}: match.path must start with '/'`);
      }
      return {
        name: r.name ?? `#${i}`,
        rawPattern: r.match.path,
        pathSegs: splitPath(r.match.path),
        methods: r.match.methods ? new Set(r.match.methods.map((m) => m.toUpperCase())) : null,
        restrict: new Set(r.restrict ?? []),
        redactHeaders: (r.redact?.headers ?? []).map((h) => h.toLowerCase()),
        redactQueryParams: (r.redact?.query_params ?? []).map((q) => q.toLowerCase()),
        redactPaths: (r.redact?.json_fields ?? []).map((p) => {
          if (!p.startsWith('$.')) throw new Error(`optic.yaml: json field ${p} must start with '$.'`);
          return p.slice(2).split('.');
        }),
        labels: r.labels ?? null,
        meters: parseMeters(r.meter, r.name ?? `#${i}`),
        sample: typeof r.sample === 'number' ? r.sample : null,
        keepErrors: r.keep_errors === true,
        keepSlowerThanMs: parseDuration(r.keep_slower_than),
      };
    });
  }

  /** Resolve the effective policy for one request (mirrors Engine.Evaluate). */
  evaluate(method, urlPath) {
    const policy = {
      captureRequestBody: this.defaults.request_body,
      captureResponseBody: this.defaults.response_body,
      captureHeaders: this.defaults.headers,
      captureLimit: this.captureLimit,
      redactHeaders: new Set(),
      redactQueryParams: new Set(),
      redactPaths: [],
      labels: {},
      meters: {},
      matchedRules: [],
      routePattern: '',
      sampleRate: 1.0,
      keepErrors: false,
      keepSlowerThanMs: null,
    };
    const segs = splitPath(urlPath);
    for (const r of this.rules) {
      if (r.methods && !r.methods.has(method)) continue;
      if (!matchSegments(r.pathSegs, segs)) continue;
      policy.matchedRules.push(r.name);
      policy.routePattern = r.rawPattern;
      if (r.sample !== null) policy.sampleRate = r.sample;
      if (r.restrict.has('request_body')) policy.captureRequestBody = false;
      if (r.restrict.has('response_body')) policy.captureResponseBody = false;
      if (r.restrict.has('headers')) policy.captureHeaders = false;
      for (const h of r.redactHeaders) policy.redactHeaders.add(h);
      for (const q of r.redactQueryParams) policy.redactQueryParams.add(q);
      policy.redactPaths.push(...r.redactPaths);
      if (r.labels) Object.assign(policy.labels, r.labels);
      Object.assign(policy.meters, r.meters);
      if (r.keepErrors) policy.keepErrors = true;
      if (r.keepSlowerThanMs !== null) {
        policy.keepSlowerThanMs =
          policy.keepSlowerThanMs === null
            ? r.keepSlowerThanMs
            : Math.min(policy.keepSlowerThanMs, r.keepSlowerThanMs);
      }
    }
    return policy;
  }
}

/** Mask policy-listed headers; header names are matched case-insensitively. */
function sanitizeHeaders(headers, policy) {
  const out = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    out[name] = policy.redactHeaders.has(name.toLowerCase())
      ? REDACTED
      : Array.isArray(value)
        ? value.join(', ')
        : String(value);
  }
  return out;
}

/**
 * Walk one dotted path and mask the addressed value.
 * `*` = any key at one level; `**` = any depth; arrays traverse implicitly.
 */
function redactPath(node, path) {
  if (path.length === 0 || node === null || typeof node !== 'object') return node;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) node[i] = redactPath(node[i], path);
    return node;
  }
  const [seg, ...rest] = path;
  if (seg === '**') {
    if (rest.length > 0) redactPath(node, rest); // may match at this level…
    for (const key of Object.keys(node)) node[key] = redactPath(node[key], path); // …and deeper
    return node;
  }
  if (seg === '*') {
    for (const key of Object.keys(node)) {
      node[key] = rest.length === 0 ? REDACTED : redactPath(node[key], rest);
    }
    return node;
  }
  if (Object.prototype.hasOwnProperty.call(node, seg)) {
    node[seg] = rest.length === 0 ? REDACTED : redactPath(node[seg], rest);
  }
  return node;
}

/** Redact a JSON body string per policy; non-JSON returns a size summary. */
function redactBody(raw, contentType, policy) {
  if (!raw || raw.length === 0) return '';
  if ((contentType ?? '').includes('json')) {
    try {
      let doc = JSON.parse(raw);
      for (const p of policy.redactPaths) doc = redactPath(doc, p);
      return JSON.stringify(doc);
    } catch {
      /* fall through to summary */
    }
  }
  return `<${contentType || 'unknown'} body, ${Buffer.byteLength(raw)} bytes captured>`;
}

/**
 * Whether the BODY may be stored for this exchange.
 *
 * Mirrors engine.Policy.KeepBody. Two details matter for parity: the record is
 * ALWAYS emitted — metrics and metadata are never sampled — and keep_errors
 * means 5xx, not 4xx. A 404 is usually the client's problem, and rescuing it
 * would defeat the sampling it is meant to work alongside.
 */
function keepBody(policy, drew, status, elapsedMs) {
  if (drew) return true;
  if (policy.keepErrors && status >= 500) return true;
  return policy.keepSlowerThanMs !== null && elapsedMs >= policy.keepSlowerThanMs;
}

/** Whether any tail rule applies, so bytes must be buffered up front. */
function tailSampled(policy) {
  return policy.keepErrors || policy.keepSlowerThanMs !== null;
}

/** `meter: {name: "$.usage.total_tokens"}` -> {name: [["usage","total_tokens"]]}. */
function parseMeters(spec, ruleName) {
  const out = {};
  for (const [name, paths] of Object.entries(spec ?? {})) {
    out[name] = (Array.isArray(paths) ? paths : [paths]).map((p) => {
      if (!String(p).startsWith('$.')) {
        throw new Error(`optic.yaml rule ${ruleName}: meter ${name} path ${p} must start with '$.'`);
      }
      return String(p).slice(2).split('.');
    });
  }
  return out;
}

/** Go-style durations ("250ms", "1s") — optic.yaml is written for the Go agent. */
function parseDuration(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  if (s.endsWith('ms')) return Number(s.slice(0, -2));
  if (s.endsWith('s')) return Number(s.slice(0, -1)) * 1000;
  if (s.endsWith('m')) return Number(s.slice(0, -1)) * 60000;
  const n = Number(s);
  return Number.isNaN(n) ? null : n;
}

/**
 * Mask named query parameters, keeping order and everything else. A credential
 * in a query string is still a credential, and it lands in the recorded URL
 * rather than in a header — a separate place needing a separate rule.
 */
function sanitizeQuery(query, policy) {
  if (!query || policy.redactQueryParams.size === 0) return query ?? '';
  return query
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      if (eq < 0) return pair;
      const key = pair.slice(0, eq);
      return policy.redactQueryParams.has(key.toLowerCase()) ? `${key}=${REDACTED}` : pair;
    })
    .join('&');
}

/** Walk a dotted path summing numbers, supporting `*` and `**`. Mirrors the Go engine. */
function sumNumeric(node, path, acc) {
  if (node === null || node === undefined) return;
  if (path.length === 0) {
    if (typeof node === 'number' && Number.isFinite(node)) {
      acc.sum += node;
      acc.found = true;
    }
    return;
  }
  if (Array.isArray(node)) {
    for (const child of node) sumNumeric(child, path, acc);
    return;
  }
  if (typeof node !== 'object') return;
  const [seg, ...rest] = path;
  if (seg === '**') {
    if (rest.length) sumNumeric(node, rest, acc);
    for (const child of Object.values(node)) sumNumeric(child, path, acc);
    return;
  }
  if (seg === '*') {
    for (const child of Object.values(node)) sumNumeric(child, rest, acc);
    return;
  }
  if (seg in node) sumNumeric(node[seg], rest, acc);
}

/**
 * Pull numeric usage out of a response body.
 *
 * Reads the RAW bytes, not the stored body: metering is independent of
 * capture, which is what lets a rule keep a prompt private while still
 * counting the tokens in it.
 */
function extractMeters(raw, policy) {
  const out = {};
  if (!raw || Object.keys(policy.meters).length === 0) return out;
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch {
    return out;
  }
  for (const [name, paths] of Object.entries(policy.meters)) {
    const acc = { sum: 0, found: false };
    for (const p of paths) sumNumeric(doc, p, acc);
    if (acc.found) out[name] = acc.sum;
  }
  return out;
}

/** First value at a dotted path, read from the ALREADY-REDACTED body. */
function firstString(doc, spec) {
  if (!doc || !String(spec).startsWith('$.')) return '';
  const walk = (node, path) => {
    if (node === null || node === undefined) return undefined;
    if (path.length === 0) {
      return typeof node === 'object' ? undefined : String(node);
    }
    if (Array.isArray(node)) {
      for (const child of node) {
        const hit = walk(child, path);
        if (hit !== undefined) return hit;
      }
      return undefined;
    }
    if (typeof node !== 'object') return undefined;
    const [seg, ...rest] = path;
    if (seg === '**') {
      if (rest.length) {
        const here = walk(node, rest);
        if (here !== undefined) return here;
      }
      for (const child of Object.values(node)) {
        const hit = walk(child, path);
        if (hit !== undefined) return hit;
      }
      return undefined;
    }
    if (seg === '*') {
      for (const child of Object.values(node)) {
        const hit = walk(child, rest);
        if (hit !== undefined) return hit;
      }
      return undefined;
    }
    return seg in node ? walk(node[seg], rest) : undefined;
  };
  return walk(doc, String(spec).slice(2).split('.')) ?? '';
}

/**
 * Resolve one label source.
 *
 * Sources are `kind:key`, optionally followed by `|<regex>` whose single
 * capture group narrows the value — that is how `header:X-Region|^([a-z]{2})-`
 * turns eu-west-1 into eu. The engines must agree here, or the same optic.yaml
 * produces different Prometheus series depending on which runtime served the
 * request.
 */
function labelValue(src, { headers = {}, query = {}, path = '', requestBody, responseBody }) {
  const spec = String(src);
  const bar = spec.indexOf('|');
  const head = bar < 0 ? spec : spec.slice(0, bar);
  const regex = bar < 0 ? null : spec.slice(bar + 1);

  const colon = head.indexOf(':');
  const kind = colon < 0 ? head : head.slice(0, colon);
  const key = colon < 0 ? '' : head.slice(colon + 1);

  let value = '';
  switch (kind) {
    case 'header':
      value = String(headers[key.toLowerCase()] ?? '');
      break;
    case 'query':
      value = String(query[key] ?? '');
      break;
    case 'static':
      value = key;
      break;
    case 'path': {
      const segs = splitPath(path);
      const idx = Number(key);
      value = Number.isInteger(idx) && idx >= 1 && idx <= segs.length ? segs[idx - 1] : '';
      break;
    }
    case 'json':
      value = firstString(requestBody, key);
      break;
    case 'json_response':
      value = firstString(responseBody, key);
      break;
    default:
      value = '';
  }

  if (!regex || !value) return value;
  const m = new RegExp(regex).exec(value);
  if (!m) return '';
  // One capture group narrows the value; no group means "matched, keep it all".
  return m.length > 1 ? (m[1] ?? '') : value;
}

module.exports = {
  Engine,
  keepBody,
  tailSampled,
  sanitizeHeaders,
  sanitizeQuery,
  redactBody,
  redactPath,
  matchSegments,
  splitPath,
  extractMeters,
  labelValue,
  firstString,
  REDACTED,
};

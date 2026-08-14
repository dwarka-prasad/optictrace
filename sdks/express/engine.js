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
        redactPaths: (r.redact?.json_fields ?? []).map((p) => {
          if (!p.startsWith('$.')) throw new Error(`optic.yaml: json field ${p} must start with '$.'`);
          return p.slice(2).split('.');
        }),
        labels: r.labels ?? null,
        sample: typeof r.sample === 'number' ? r.sample : null,
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
      redactPaths: [],
      labels: {},
      matchedRules: [],
      routePattern: '',
      sampleRate: 1.0,
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
      policy.redactPaths.push(...r.redactPaths);
      if (r.labels) Object.assign(policy.labels, r.labels);
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

module.exports = { Engine, sanitizeHeaders, redactBody, redactPath, matchSegments, splitPath, REDACTED };

// Thin typed client for the OpticTrace agent's admin API.
// Same-origin when the dashboard is served by the agent itself;
// NEXT_PUBLIC_OPTIC_API points at the agent during `next dev`.

export const API_BASE = process.env.NEXT_PUBLIC_OPTIC_API ?? '';

export interface TimeBucket {
  time: string;
  count: number;
  errors: number;
  avg_latency_ms: number;
}

export interface RouteStat {
  route: string;
  method: string;
  count: number;
  errors: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
}

export interface Stats {
  total: number;
  errors: number;
  error_rate: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  status_counts: Record<string, number>;
  series: TimeBucket[];
  top_routes: RouteStat[];
}

export interface LogRecord {
  id: number;
  time: string;
  service: string;
  method: string;
  path: string;
  route: string;
  status: number;
  duration_ms: number;
  remote: string;
  source: string;
  request_headers?: Record<string, string>;
  response_headers?: Record<string, string>;
  request_body?: string;
  response_body?: string;
  req_truncated?: boolean;
  resp_truncated?: boolean;
  req_bytes: number;
  resp_bytes: number;
  labels?: Record<string, string>;
  matched_rules?: string[];
  /** Long-lived response (SSE, chunked, an upgraded connection). Its duration
   *  is a connection lifetime, not a latency, which is why it is excluded from
   *  percentiles — worth showing so a 600s row does not read as a disaster. */
  stream?: boolean;
  /** W3C trace context. Every hop of one request shares trace_id, so several
   *  services reporting into one store can be reassembled into a tree. */
  trace_id?: string;
  span_id?: string;
  parent_span_id?: string;
}

export interface LogQuery {
  q?: string;
  method?: string;
  path?: string;
  status_min?: number;
  status_max?: number;
  since?: string;
  limit?: number;
  offset?: number;
  /** Every hop of one request. */
  trace?: string;
  /** Tag filters, sent as label.<name>=<value>. All must match. */
  labels?: Record<string, string>;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

export const fetchStats = (window: string, bucket: string) =>
  get<Stats>(`/api/stats?window=${window}&bucket=${bucket}`);

/** Renders a LogQuery as query-string params, expanding tag filters into the
 *  label.<name>=<value> form the API expects. Shared by fetchLogs and
 *  exportUrl so an export always matches exactly what the table shows. */
export function logParams(query: LogQuery): URLSearchParams {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([k, v]) => {
    if (k === 'labels') return;
    if (v !== undefined && v !== '' && v !== 0) params.set(k, String(v));
  });
  Object.entries(query.labels ?? {}).forEach(([k, v]) => {
    if (k && v) params.set(`label.${k}`, v);
  });
  return params;
}

export const fetchLogs = (query: LogQuery) =>
  get<{ total: number; records: LogRecord[] }>(`/api/logs?${logParams(query)}`);

/** Every hop of one request, oldest first so it reads as a sequence. */
export const fetchTrace = async (traceId: string) => {
  const res = await get<{ total: number; records: LogRecord[] }>(
    `/api/logs?trace=${encodeURIComponent(traceId)}&limit=200`,
  );
  return res.records.slice().sort((a, b) => a.time.localeCompare(b.time));
};

export const fetchConfig = () =>
  get<{ path: string; raw: string; valid: boolean; error?: string; service?: string; rules?: number }>(
    '/api/config',
  );

export async function validateConfig(yaml: string) {
  const res = await fetch(`${API_BASE}/api/config/validate`, {
    method: 'POST',
    body: yaml,
  });
  return res.json() as Promise<{ valid: boolean; error?: string; service?: string; rules?: number }>;
}

export async function reloadConfig() {
  const res = await fetch(`${API_BASE}/api/reload`, { method: 'POST' });
  return res.json() as Promise<{ reloaded?: boolean; error?: string }>;
}

export interface RouteDetail extends RouteStat {
  p50_latency_ms: number;
  p99_latency_ms: number;
  req_bytes: number;
  resp_bytes: number;
}

export const fetchRoutes = (window: string) =>
  get<{ routes: RouteDetail[] }>(`/api/routes?window=${window}`);

export interface RuleView {
  name: string;
  path: string;
  methods?: string[];
  restrict?: string[];
  redact_headers: number;
  redact_json_fields: number;
  labels: number;
  sample?: number;
  matches: number;
}

export const fetchRuleStats = (window: string) =>
  get<{ rules: RuleView[]; window_total: number }>(`/api/rules/stats?window=${window}`);

export interface ExporterStat {
  name: string;
  type: string;
  delivered: number;
  failed: number;
  dropped: number;
  queue_len: number;
}

export interface SystemInfo {
  version: string;
  uptime_seconds: number;
  service?: string;
  upstream?: string;
  rules?: number;
  config_path: string;
  store: { enabled: boolean; records?: number };
  exporters: ExporterStat[];
}

export const fetchSystem = () => get<SystemInfo>('/api/system');

export interface ConsumerUsage {
  consumer: string;
  requests: number;
  errors: number;
  req_bytes: number;
  resp_bytes: number;
  duration_ms_total: number;
  meters?: Record<string, number>;
  cost?: Record<string, number>; // includes "total"
}

export interface UsageResponse {
  label: string;
  currency: string;
  billing: boolean;
  consumers: ConsumerUsage[];
}

export const fetchUsage = (window: string, label?: string) =>
  get<UsageResponse>(
    `/api/usage?window=${window}${label ? `&label=${encodeURIComponent(label)}` : ''}`,
  );

export const usageCsvUrl = (window: string, label?: string) =>
  `${API_BASE}/api/usage?window=${window}&format=csv${label ? `&label=${encodeURIComponent(label)}` : ''}`;

/** Tag names present in recent traffic.
 *
 *  Derived from stored records rather than from the config on purpose: a tag a
 *  rule declares but no request ever populates is a dead option in a picker,
 *  and offering it would send someone to an empty breakdown wondering what
 *  they did wrong. */
export async function fetchLabelNames(): Promise<string[]> {
  const res = await get<{ records: LogRecord[] }>('/api/logs?limit=100');
  const names = new Set<string>();
  res.records.forEach((r) =>
    Object.entries(r.labels ?? {}).forEach(([k, v]) => {
      if (v) names.add(k);
    }),
  );
  return [...names].sort();
}

/** Download URL for /api/export honoring the inspector's current filters. */
export function exportUrl(format: 'csv' | 'jsonl', query: LogQuery) {
  // Reuses logParams so an export carries the tag filters too. Downloading
  // "everything" when the table showed one tenant would be a bad surprise.
  const { limit: _l, offset: _o, ...rest } = query;
  const params = logParams(rest);
  params.set('format', format);
  return `${API_BASE}/api/export?${params}`;
}

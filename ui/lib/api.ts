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
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

export const fetchStats = (window: string, bucket: string) =>
  get<Stats>(`/api/stats?window=${window}&bucket=${bucket}`);

export const fetchLogs = (query: LogQuery) => {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([k, v]) => {
    if (v !== undefined && v !== '' && v !== 0) params.set(k, String(v));
  });
  return get<{ total: number; records: LogRecord[] }>(`/api/logs?${params}`);
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

export const fetchUsage = (window: string) =>
  get<UsageResponse>(`/api/usage?window=${window}`);

export const usageCsvUrl = (window: string) =>
  `${API_BASE}/api/usage?window=${window}&format=csv`;

/** Download URL for /api/export honoring the inspector's current filters. */
export function exportUrl(format: 'csv' | 'jsonl', query: LogQuery) {
  const params = new URLSearchParams({ format });
  Object.entries(query).forEach(([k, v]) => {
    if (v !== undefined && v !== '' && v !== 0 && k !== 'limit' && k !== 'offset') {
      params.set(k, String(v));
    }
  });
  return `${API_BASE}/api/export?${params}`;
}

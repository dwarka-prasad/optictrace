'use client';

import { useCallback, useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, Download, GitBranch, RefreshCw, Search, ShieldCheck, Tag, Terminal, X } from 'lucide-react';
import {
  exportUrl,
  fetchLogs,
  fetchSpanLogs,
  fetchTrace,
  type AppLogLine,
  type LogQuery,
  type LogRecord,
} from '@/lib/api';
import { MethodBadge, StatusBadge, StreamBadge } from '@/components/badges';

const PAGE_SIZE = 25;

export default function Inspector() {
  const [records, setRecords] = useState<LogRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<LogRecord | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [q, setQ] = useState('');
  const [method, setMethod] = useState('');
  const [statusClass, setStatusClass] = useState('');
  const [since, setSince] = useState('');
  // Tag filters. The multi-tenant question — "show me only this partner" —
  // which the API has supported for a while and the UI could not ask.
  const [labels, setLabels] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    try {
      const statusRange =
        statusClass === '' ? {} : { status_min: Number(statusClass), status_max: Number(statusClass) + 99 };
      const res = await fetchLogs({
        q,
        method,
        since,
        labels,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        ...statusRange,
      });
      setRecords(res.records);
      setTotal(res.total);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [q, method, statusClass, since, labels, page]);

  useEffect(() => {
    const t = setTimeout(load, 250); // debounce typing
    return () => clearTimeout(t);
  }, [load]);

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Request Inspector</h1>
        <div className="flex items-center gap-2">
          <ExportButtons query={currentQuery(q, method, statusClass, since, labels)} />
          <button
            onClick={load}
            className="flex items-center gap-1.5 rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="panel flex flex-wrap items-center gap-2 p-3">
        <div className="relative min-w-56 flex-1">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[var(--muted)]" />
          <input
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(0);
            }}
            placeholder="Search path or payload…"
            className="w-full rounded-lg border border-[var(--border)] bg-transparent py-1.5 pl-8 pr-3 text-sm outline-none focus:border-[var(--accent)]/60"
          />
        </div>
        <FilterSelect value={method} onChange={(v) => { setMethod(v); setPage(0); }}
          options={[['', 'Any method'], ['GET', 'GET'], ['POST', 'POST'], ['PUT', 'PUT'], ['PATCH', 'PATCH'], ['DELETE', 'DELETE']]} />
        <FilterSelect value={statusClass} onChange={(v) => { setStatusClass(v); setPage(0); }}
          options={[['', 'Any status'], ['200', '2xx'], ['300', '3xx'], ['400', '4xx'], ['500', '5xx']]} />
        <FilterSelect value={since} onChange={(v) => { setSince(v); setPage(0); }}
          options={[['', 'All time'], ['15m', 'Last 15m'], ['1h', 'Last 1h'], ['6h', 'Last 6h'], ['24h', 'Last 24h']]} />

        {Object.entries(labels).map(([k, v]) => (
          <button
            key={k}
            onClick={() => {
              const next = { ...labels };
              delete next[k];
              setLabels(next);
              setPage(0);
            }}
            title="Remove this tag filter"
            className="flex items-center gap-1 rounded-lg border border-[var(--accent)]/50 bg-[var(--accent)]/10 px-2 py-1 text-xs text-[var(--accent)]"
          >
            <Tag className="h-3 w-3" />
            <span className="font-mono">{k}={v}</span>
            <X className="h-3 w-3 opacity-70" />
          </button>
        ))}
        {Object.keys(labels).length > 1 && (
          <span className="text-[11px] text-[var(--muted)]">all tags must match</span>
        )}
      </div>

      {error && (
        <div className="panel border-[var(--bad)]/40 p-4 text-sm text-[var(--bad)]">{error}</div>
      )}

      <div className="flex gap-4">
        {/* Log table */}
        <div className={`panel overflow-hidden transition-all ${selected ? 'w-1/2' : 'w-full'}`}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-[var(--muted)]">
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Method</th>
                  <th className="px-3 py-2 font-medium">Path</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Tags</th>
                  <th className="px-3 py-2 text-right font-medium">Latency</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr
                    key={r.id}
                    onClick={() => setSelected(r)}
                    className={`cursor-pointer border-t border-[var(--border)]/60 hover:bg-white/[.03] ${
                      selected?.id === r.id ? 'bg-[var(--accent)]/[.07]' : ''
                    }`}
                  >
                    <td className="whitespace-nowrap px-3 py-2 text-xs text-[var(--muted)]">
                      {new Date(r.time).toLocaleTimeString()}
                    </td>
                    <td className="px-3 py-2"><MethodBadge method={r.method} /></td>
                    <td className="max-w-64 truncate px-3 py-2 font-mono text-xs">{r.path}</td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1.5">
                        <StatusBadge status={r.status} />
                        {r.stream && <StreamBadge />}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <RowTags
                        record={r}
                        onPick={(k, v) => {
                          setLabels({ ...labels, [k]: v });
                          setPage(0);
                        }}
                      />
                    </td>
                    <td className="px-3 py-2 text-right text-xs">{r.duration_ms.toFixed(1)}ms</td>
                  </tr>
                ))}
                {records.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-10 text-center text-[var(--muted)]">
                      No captured requests match these filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between border-t border-[var(--border)] px-3 py-2 text-xs text-[var(--muted)]">
            <span>{total} records</span>
            <div className="flex items-center gap-2">
              <button disabled={page === 0} onClick={() => setPage(page - 1)}
                className="rounded p-1 hover:bg-white/5 disabled:opacity-30"><ChevronLeft className="h-4 w-4" /></button>
              <span>{page + 1} / {pages}</span>
              <button disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}
                className="rounded p-1 hover:bg-white/5 disabled:opacity-30"><ChevronRight className="h-4 w-4" /></button>
            </div>
          </div>
        </div>

        {/* Detail panel */}
        {selected && (
          <DetailPanel
            record={selected}
            onClose={() => setSelected(null)}
            onPickTag={(k, v) => {
              setLabels({ ...labels, [k]: v });
              setPage(0);
            }}
            onSelectRecord={setSelected}
          />
        )}
      </div>
    </div>
  );
}

function currentQuery(
  q: string,
  method: string,
  statusClass: string,
  since: string,
  labels: Record<string, string>,
): LogQuery {
  const range =
    statusClass === '' ? {} : { status_min: Number(statusClass), status_max: Number(statusClass) + 99 };
  return { q, method, since, labels, ...range };
}

// Downloads matching records via /api/export — same filters as the table.
function ExportButtons({ query }: { query: LogQuery }) {
  return (
    <div className="flex overflow-hidden rounded-lg border border-[var(--border)] text-xs text-[var(--muted)]">
      <span className="flex items-center gap-1.5 border-r border-[var(--border)] px-2.5 py-1.5">
        <Download className="h-3.5 w-3.5" /> Export
      </span>
      <a href={exportUrl('csv', query)} download className="border-r border-[var(--border)] px-2.5 py-1.5 hover:bg-white/5 hover:text-[var(--text)]">
        CSV
      </a>
      <a href={exportUrl('jsonl', query)} download className="px-2.5 py-1.5 hover:bg-white/5 hover:text-[var(--text)]">
        JSONL
      </a>
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-[var(--border)] bg-[var(--panel)] px-2.5 py-1.5 text-xs outline-none focus:border-[var(--accent)]/60"
    >
      {options.map(([v, label]) => (
        <option key={v} value={v}>{label}</option>
      ))}
    </select>
  );
}

/** Up to two tags per row, clickable to filter. Two because a row with six
 *  chips is unreadable and the table is for scanning — the rest are in the
 *  detail panel. */
function RowTags({
  record,
  onPick,
}: {
  record: LogRecord;
  onPick: (k: string, v: string) => void;
}) {
  const entries = Object.entries(record.labels ?? {}).filter(([, v]) => v !== '');
  if (entries.length === 0) return <span className="text-xs text-[var(--muted)]">—</span>;
  const shown = entries.slice(0, 2);
  return (
    <div className="flex flex-wrap items-center gap-1">
      {shown.map(([k, v]) => (
        <button
          key={k}
          onClick={(e) => {
            e.stopPropagation(); // don't also open the detail panel
            onPick(k, v);
          }}
          title={`Filter to ${k}=${v}`}
          className="rounded border border-[var(--border)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--muted)] hover:border-[var(--accent)]/60 hover:text-[var(--accent)]"
        >
          {k}={v}
        </button>
      ))}
      {entries.length > shown.length && (
        <span className="text-[10px] text-[var(--muted)]">+{entries.length - shown.length}</span>
      )}
    </div>
  );
}

/** Every hop of one request, as a tree.
 *
 *  This is what a trace id is for: several services reporting into one store
 *  are otherwise a flat list with no way to ask "what did this call actually
 *  do". Indentation follows parent_span_id, so the shape is the real call
 *  graph rather than arrival order. */
function TraceTree({
  record,
  onSelectRecord,
}: {
  record: LogRecord;
  onSelectRecord: (r: LogRecord) => void;
}) {
  const [hops, setHops] = useState<LogRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!record.trace_id) return;
    let live = true;
    fetchTrace(record.trace_id)
      .then((rs) => live && setHops(rs))
      .catch((e) => live && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
  }, [record.trace_id]);

  if (!record.trace_id) return null;

  const total = hops?.reduce((max, h) => Math.max(max, h.duration_ms), 0) ?? 0;

  // depth by walking parent links; a hop whose parent is not in the result
  // (a service that does not report here) is shown at the root rather than
  // hidden, because silently dropping it would misrepresent the call.
  const bySpan = new Map((hops ?? []).map((h) => [h.span_id ?? '', h]));
  const depthOf = (h: LogRecord): number => {
    let d = 0;
    let cur = h;
    const guard = new Set<string>();
    while (cur.parent_span_id && bySpan.has(cur.parent_span_id)) {
      if (guard.has(cur.span_id ?? '')) break; // cycles cannot happen, but a UI must not hang if they do
      guard.add(cur.span_id ?? '');
      cur = bySpan.get(cur.parent_span_id)!;
      d += 1;
    }
    return d;
  };

  return (
    <Section
      icon={<GitBranch className="h-3.5 w-3.5" />}
      title={`Request trace${hops ? ` · ${hops.length} hop${hops.length === 1 ? '' : 's'}` : ''}`}
    >
      <div className="mb-2 break-all font-mono text-[10px] text-[var(--muted)]">{record.trace_id}</div>
      {error && <div className="text-xs text-[var(--bad)]">{error}</div>}
      {!hops && !error && <div className="text-xs text-[var(--muted)]">loading…</div>}
      {hops?.length === 1 && (
        <div className="mb-2 text-[11px] text-[var(--muted)]">
          Only this hop reported. Put an OpticTrace sidecar in front of the services it
          calls, and they appear here.
        </div>
      )}
      <div className="space-y-1">
        {hops?.map((h) => (
          <button
            key={h.id}
            onClick={() => onSelectRecord(h)}
            className={`flex w-full items-center gap-2 rounded px-1.5 py-1 text-left text-xs hover:bg-white/[.04] ${
              h.id === record.id ? 'bg-[var(--accent)]/[.08]' : ''
            }`}
            style={{ paddingLeft: `${6 + depthOf(h) * 16}px` }}
          >
            <span className="w-20 shrink-0 truncate text-[var(--muted)]">{h.service || '—'}</span>
            <MethodBadge method={h.method} />
            <span className="flex-1 truncate font-mono text-[11px]">{h.path}</span>
            <StatusBadge status={h.status} />
            <span className="w-16 shrink-0 text-right tabular-nums text-[var(--muted)]">
              {h.duration_ms.toFixed(1)}ms
            </span>
            {/* A bar, so the hop that actually cost the time is obvious. */}
            <span className="hidden w-16 shrink-0 sm:block">
              <span
                className="block h-1 rounded bg-[var(--accent)]/50"
                style={{ width: `${total ? Math.max(3, (h.duration_ms / total) * 100) : 0}%` }}
              />
            </span>
          </button>
        ))}
      </div>
    </Section>
  );
}

function DetailPanel({
  record: r,
  onClose,
  onPickTag,
  onSelectRecord,
}: {
  record: LogRecord;
  onClose: () => void;
  onPickTag: (k: string, v: string) => void;
  onSelectRecord: (r: LogRecord) => void;
}) {
  const restricted = !r.request_headers && !r.request_body && !r.response_body;
  return (
    <div className="panel w-1/2 self-start overflow-hidden">
      <div className="flex items-center justify-between border-b border-[var(--border)] px-4 py-3">
        <div className="flex items-center gap-2 text-sm">
          <MethodBadge method={r.method} />
          <span className="font-mono text-xs">{r.path}</span>
          <StatusBadge status={r.status} />
        </div>
        <button onClick={onClose} className="text-[var(--muted)] hover:text-[var(--text)]">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="max-h-[70vh] space-y-4 overflow-y-auto p-4 text-xs">
        <MetaGrid r={r} />
        {restricted && (
          <div className="flex items-center gap-2 rounded-lg border border-[var(--good)]/30 bg-[var(--good)]/5 p-3 text-[var(--good)]">
            <ShieldCheck className="h-4 w-4 shrink-0" />
            Payload capture restricted by optic.yaml — only metadata was recorded.
          </div>
        )}
        {r.matched_rules && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[var(--muted)]">Matched rules:</span>
            {r.matched_rules.map((m) => (
              <span key={m} className="rounded-full border border-[var(--accent)]/30 px-2 py-0.5 text-[var(--accent)]">{m}</span>
            ))}
          </div>
        )}
        {r.labels && Object.keys(r.labels).length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[var(--muted)]">Tags:</span>
            {Object.entries(r.labels).map(([k, v]) =>
              v ? (
                <button
                  key={k}
                  onClick={() => onPickTag(k, v)}
                  title={`Filter to ${k}=${v}`}
                  className="rounded-full border border-[var(--border)] px-2 py-0.5 hover:border-[var(--accent)]/60 hover:text-[var(--accent)]"
                >
                  {k}={v}
                </button>
              ) : (
                // An empty value means the rule declared the tag but the
                // request carried nothing — worth showing, since a silently
                // absent tag is the usual symptom of a mistyped source.
                <span
                  key={k}
                  title="Declared by a rule, but this request carried no value"
                  className="rounded-full border border-dashed border-[var(--border)] px-2 py-0.5 text-[var(--muted)]"
                >
                  {k}=∅
                </span>
              ),
            )}
          </div>
        )}
        <TraceTree record={r} onSelectRecord={onSelectRecord} />
        <AppLogs spanId={r.span_id} />
        {r.request_headers && <KV title="Request headers" data={r.request_headers} />}
        {r.request_body && <Body title="Request body" body={r.request_body} truncated={r.req_truncated} />}
        {r.response_headers && <KV title="Response headers" data={r.response_headers} />}
        {r.response_body && <Body title="Response body" body={r.response_body} truncated={r.resp_truncated} />}
      </div>
    </div>
  );
}

/** What the application logged while serving this request.
 *
 *  Correlated by span id, which OpticTrace put in the traceparent it forwarded
 *  — so these lines belong to this request as a fact rather than because their
 *  timestamps were close. Renders nothing at all when the feature is off, so a
 *  disabled optional feature is not a permanently empty box in the UI. */
function AppLogs({ spanId }: { spanId?: string }) {
  const [lines, setLines] = useState<AppLogLine[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    if (!spanId) {
      setLines([]);
      return;
    }
    setLines(null);
    setError(null);
    fetchSpanLogs(spanId)
      .then((l) => live && setLines(l))
      .catch((e) => live && setError(String(e)));
    return () => {
      live = false;
    };
  }, [spanId]);

  if (!spanId) return null;
  if (lines !== null && lines.length === 0 && !error) return null;

  return (
    <Section icon={<Terminal className="h-3.5 w-3.5" />} title="Application logs">
      {error && <div className="text-[var(--bad)]">{error}</div>}
      {lines === null && <div className="text-[var(--muted)]">Loading…</div>}
      <div className="space-y-1 font-mono text-[11px] leading-relaxed">
        {lines?.map((l) => (
          <div key={l.id} className="flex gap-2 border-b border-[var(--border)]/30 pb-1">
            <span className="shrink-0 text-[var(--muted)]">
              {new Date(l.time).toLocaleTimeString(undefined, { hour12: false })}
            </span>
            <LevelBadge level={l.level} />
            <span className="min-w-0 break-words">
              {l.message}
              {l.truncated && <span className="text-[var(--muted)]"> …(truncated)</span>}
              {l.fields && Object.keys(l.fields).length > 0 && (
                <span className="ml-2 text-[var(--muted)]">
                  {Object.entries(l.fields).map(([k, v]) => `${k}=${v}`).join(' ')}
                </span>
              )}
            </span>
          </div>
        ))}
      </div>
    </Section>
  );
}

/** Severity as colour as well as text: an error should be findable by
 *  scanning, not by reading every line. */
function LevelBadge({ level }: { level: string }) {
  const tone =
    level === 'error' || level === 'fatal'
      ? 'text-[var(--bad)]'
      : level === 'warn'
        ? 'text-[var(--warn)]'
        : level === 'debug' || level === 'trace'
          ? 'text-[var(--muted)]'
          : 'text-[var(--good)]';
  return <span className={`w-10 shrink-0 uppercase ${tone}`}>{level}</span>;
}

function MetaGrid({ r }: { r: LogRecord }) {
  const rows: [string, string][] = [
    ['Time', new Date(r.time).toLocaleString()],
    ['Latency', `${r.duration_ms.toFixed(2)} ms`],
    ['Route', r.route],
    ['Source', r.source],
    ['Remote', r.remote],
    ['Size', `${r.req_bytes}B → ${r.resp_bytes}B`],
  ];
  if (r.stream) rows.splice(2, 0, ['Kind', 'stream (duration is a connection lifetime)']);
  if (r.span_id) rows.push(['Span', r.span_id]);
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
      {rows.map(([k, v]) => (
        <div key={k} className="flex justify-between gap-2 border-b border-[var(--border)]/40 pb-1">
          <span className="text-[var(--muted)]">{k}</span>
          <span className="truncate font-mono">{v}</span>
        </div>
      ))}
    </div>
  );
}

/** A titled block, matching the KV/Body idiom used elsewhere in this panel. */
function Section({
  icon,
  title,
  children,
}: {
  icon?: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="mb-1.5 flex items-center gap-1.5 font-medium text-[var(--muted)]">
        {icon}
        {title}
      </h3>
      <div className="rounded-lg border border-[var(--border)] p-2">{children}</div>
    </div>
  );
}

function KV({ title, data }: { title: string; data: Record<string, string> }) {
  return (
    <div>
      <h3 className="mb-1.5 font-medium text-[var(--muted)]">{title}</h3>
      <div className="space-y-0.5 rounded-lg border border-[var(--border)] p-2 font-mono">
        {Object.entries(data).map(([k, v]) => (
          <div key={k} className="flex gap-2">
            <span className="shrink-0 text-[var(--accent)]">{k}:</span>
            <span className={v === '[REDACTED]' ? 'text-[var(--warn)]' : ''}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Body({ title, body, truncated }: { title: string; body: string; truncated?: boolean }) {
  let pretty = body;
  try {
    pretty = JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    /* not JSON — show as-is */
  }
  return (
    <div>
      <h3 className="mb-1.5 flex items-center gap-2 font-medium text-[var(--muted)]">
        {title}
        {truncated && (
          <span className="rounded border border-[var(--warn)]/40 px-1.5 text-[10px] text-[var(--warn)]">
            truncated at capture limit
          </span>
        )}
      </h3>
      <pre className="overflow-x-auto rounded-lg border border-[var(--border)] bg-black/20 p-3 font-mono leading-relaxed">
        {highlightRedactions(pretty)}
      </pre>
    </div>
  );
}

// Render [REDACTED] markers in a distinct color so governance is visible.
function highlightRedactions(text: string) {
  const parts = text.split('[REDACTED]');
  return parts.flatMap((part, i) =>
    i < parts.length - 1
      ? [part, <span key={i} className="rounded bg-[var(--warn)]/15 px-1 text-[var(--warn)]">[REDACTED]</span>]
      : [part],
  );
}

'use client';

import { useCallback, useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, Download, RefreshCw, Search, ShieldCheck, X } from 'lucide-react';
import { exportUrl, fetchLogs, type LogQuery, type LogRecord } from '@/lib/api';
import { MethodBadge, StatusBadge } from '@/components/badges';

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

  const load = useCallback(async () => {
    try {
      const statusRange =
        statusClass === '' ? {} : { status_min: Number(statusClass), status_max: Number(statusClass) + 99 };
      const res = await fetchLogs({
        q,
        method,
        since,
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
  }, [q, method, statusClass, since, page]);

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
          <ExportButtons query={currentQuery(q, method, statusClass, since)} />
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
                    <td className="px-3 py-2"><StatusBadge status={r.status} /></td>
                    <td className="px-3 py-2 text-right text-xs">{r.duration_ms.toFixed(1)}ms</td>
                  </tr>
                ))}
                {records.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-10 text-center text-[var(--muted)]">
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
        {selected && <DetailPanel record={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  );
}

function currentQuery(q: string, method: string, statusClass: string, since: string): LogQuery {
  const range =
    statusClass === '' ? {} : { status_min: Number(statusClass), status_max: Number(statusClass) + 99 };
  return { q, method, since, ...range };
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

function DetailPanel({ record: r, onClose }: { record: LogRecord; onClose: () => void }) {
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
            <span className="text-[var(--muted)]">Labels:</span>
            {Object.entries(r.labels).map(([k, v]) => (
              <span key={k} className="rounded-full border border-[var(--border)] px-2 py-0.5">{k}={v || '∅'}</span>
            ))}
          </div>
        )}
        {r.request_headers && <KV title="Request headers" data={r.request_headers} />}
        {r.request_body && <Body title="Request body" body={r.request_body} truncated={r.req_truncated} />}
        {r.response_headers && <KV title="Response headers" data={r.response_headers} />}
        {r.response_body && <Body title="Response body" body={r.response_body} truncated={r.resp_truncated} />}
      </div>
    </div>
  );
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

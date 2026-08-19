'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { AlertTriangle, GitBranch, Layers, ScrollText, Search, X } from 'lucide-react';
import {
  fetchAppLogs,
  fetchTrace,
  fetchTraces,
  type AppLogLine,
  type LogRecord,
  type TraceSummary,
} from '@/lib/api';
import { MethodBadge, StatusBadge } from '@/components/badges';

const WINDOWS = ['15m', '1h', '6h', '24h'];

/** Traces — one row per request, however many services it touched.
 *
 *  The record list answers "what happened to this hop". This answers "what
 *  happened to this REQUEST", which is the question anyone debugging a
 *  fan-out actually has, and the one the record list cannot answer without
 *  already knowing a trace id to search for. */
export default function Traces() {
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [supported, setSupported] = useState(true);
  const [win, setWin] = useState('1h');
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [q, setQ] = useState('');
  const [selected, setSelected] = useState<TraceSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetchTraces({ window: win, errors: errorsOnly, q, limit: 100 });
      setTraces(res.traces);
      setTotal(res.total);
      setSupported(res.supported);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [win, errorsOnly, q]);

  useEffect(() => {
    load();
    // Polling pauses while a trace is open: a list that reorders under the
    // cursor mid-investigation is how you lose the thing you were reading.
    if (selected) return;
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load, selected]);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Traces</h1>
          <p className="text-xs text-[var(--muted)]">
            {total.toLocaleString()} request{total === 1 ? '' : 's'} across every service · last {win}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="relative">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--muted)]" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="path or route"
              className="w-48 rounded-lg border border-[var(--border)] bg-transparent py-1.5 pl-8 pr-2 text-xs outline-none focus:border-[var(--accent)]"
            />
          </label>
          <button
            onClick={() => setErrorsOnly((v) => !v)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition-colors ${
              errorsOnly
                ? 'border-[var(--bad)]/50 bg-[var(--bad)]/10 text-[var(--bad)]'
                : 'border-[var(--border)] text-[var(--muted)] hover:text-[var(--text)]'
            }`}
          >
            <AlertTriangle className="h-3.5 w-3.5" /> failures only
          </button>
          <div className="flex gap-1 rounded-lg border border-[var(--border)] p-1">
            {WINDOWS.map((w) => (
              <button
                key={w}
                onClick={() => setWin(w)}
                className={`rounded-md px-3 py-1 text-xs transition-colors ${
                  w === win ? 'bg-[var(--accent)]/15 text-[var(--accent)]' : 'text-[var(--muted)] hover:text-[var(--text)]'
                }`}
              >
                {w}
              </button>
            ))}
          </div>
        </div>
      </header>

      {error && (
        <div className="panel border-[var(--bad)]/40 p-3 text-xs text-[var(--bad)]">{error}</div>
      )}

      {!supported && (
        <div className="panel p-6 text-sm text-[var(--muted)]">
          <p className="mb-2 text-[var(--text)]">This store driver cannot list traces.</p>
          <p className="max-w-2xl text-xs">
            Correlation still works — every record carries its trace and span ids, and the{' '}
            <Link href="/inspector" className="text-[var(--accent)] hover:underline">
              Inspector
            </Link>{' '}
            reassembles a trace from any hop in it. Only this listing needs a driver that can
            group by trace id. The bundled sqlite, postgres and clickhouse drivers all can.
          </p>
        </div>
      )}

      {supported && (
        <div className="panel overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-[var(--muted)]">
                  <th className="px-4 py-2.5 font-medium">Started</th>
                  <th className="px-4 py-2.5 font-medium">Entry point</th>
                  <th className="px-4 py-2.5 font-medium">Status</th>
                  <th className="px-4 py-2.5 text-right font-medium">Hops</th>
                  <th className="px-4 py-2.5 text-right font-medium">Services</th>
                  <th className="px-4 py-2.5 text-right font-medium">Logs</th>
                  <th className="px-4 py-2.5 text-right font-medium">Duration</th>
                </tr>
              </thead>
              <tbody>
                {traces.map((t) => (
                  <tr
                    key={t.trace_id}
                    onClick={() => setSelected(t)}
                    className="cursor-pointer border-t border-[var(--border)]/60 hover:bg-white/[.03]"
                  >
                    <td className="whitespace-nowrap px-4 py-2 text-xs text-[var(--muted)]">
                      {new Date(t.start).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2">
                        <MethodBadge method={t.method} />
                        <span className="max-w-[22rem] truncate font-mono text-xs">{t.path || t.route}</span>
                      </div>
                      <div className="mt-0.5 flex flex-wrap gap-1.5 text-[10px] text-[var(--muted)]">
                        <span>{t.service}</span>
                        {Object.entries(t.labels ?? {})
                          .filter(([, v]) => v)
                          .slice(0, 3)
                          .map(([k, v]) => (
                            <span key={k} className="rounded bg-white/5 px-1.5 py-0.5">
                              {k}:{v}
                            </span>
                          ))}
                      </div>
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-1.5">
                        <StatusBadge status={t.status} />
                        {/* An inner failure the caller never saw. This is the
                            column that makes a trace list worth having. */}
                        {t.errors > 0 && t.status < 500 && (
                          <span
                            title={`${t.errors} inner hop(s) returned 5xx — the caller was told ${t.status}`}
                            className="rounded border border-[var(--bad)]/40 px-1.5 py-0.5 font-mono text-[10px] text-[var(--bad)]"
                          >
                            {t.errors} inner
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2 text-right tabular-nums">{t.spans}</td>
                    <td className="px-4 py-2 text-right tabular-nums text-[var(--muted)]">{t.services}</td>
                    <td className="px-4 py-2 text-right tabular-nums text-[var(--muted)]">
                      {t.log_lines < 0 ? '—' : t.log_lines}
                    </td>
                    <td className="px-4 py-2 text-right tabular-nums">{t.duration_ms.toFixed(1)}ms</td>
                  </tr>
                ))}
                {traces.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-10 text-center text-[var(--muted)]">
                      {errorsOnly ? 'No failing traces in this window.' : 'No traces in this window yet.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selected && <TracePanel trace={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

/** The waterfall: every hop placed on a shared timeline, with the log lines
 *  each one wrote underneath it.
 *
 *  Offset matters as much as width. A bar chart sorted by duration cannot tell
 *  you whether two calls ran in parallel or one after the other, and that is
 *  usually the whole question — a 300ms request made of two 120ms calls is
 *  either nearly optimal or 120ms of avoidable waiting, depending only on
 *  where the bars sit. */
function TracePanel({ trace, onClose }: { trace: TraceSummary; onClose: () => void }) {
  const [hops, setHops] = useState<LogRecord[] | null>(null);
  const [lines, setLines] = useState<AppLogLine[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    Promise.all([
      fetchTrace(trace.trace_id),
      fetchAppLogs({ trace: trace.trace_id, limit: 500 }).catch(() => ({ lines: [] as AppLogLine[] })),
    ])
      .then(([hs, ls]) => {
        if (!live) return;
        setHops(hs);
        setLines(ls.lines);
      })
      .catch((e) => live && setErr(e instanceof Error ? e.message : String(e)));
    return () => {
      live = false;
    };
  }, [trace.trace_id]);

  // A record's `time` is when the exchange FINISHED (see ext.Record.Time), so
  // a hop starts one duration earlier. Reading it as the start drew the root
  // — the last hop to finish — beginning after the children it called, which
  // is the opposite of what happened.
  const startOf = (h: LogRecord) => new Date(h.time).getTime() - h.duration_ms;
  // The timeline spans the earliest start to the latest finish, rather than
  // the root's own window: a hop that outlived its parent — a fire-and-forget
  // call, or two machines with skewed clocks — would otherwise run off the
  // right edge instead of being visible as the anomaly it is.
  const t0 = hops?.length ? Math.min(...hops.map(startOf)) : 0;
  const t1 = hops?.length ? Math.max(...hops.map((h) => new Date(h.time).getTime())) : 0;
  const span = Math.max(1, t1 - t0);

  const bySpan = useMemo(() => new Map((hops ?? []).map((h) => [h.span_id ?? '', h])), [hops]);
  const depthOf = (h: LogRecord): number => {
    let d = 0;
    let cur = h;
    const guard = new Set<string>();
    while (cur.parent_span_id && bySpan.has(cur.parent_span_id)) {
      if (guard.has(cur.span_id ?? '')) break; // cycles cannot happen; a UI must not hang if they do
      guard.add(cur.span_id ?? '');
      cur = bySpan.get(cur.parent_span_id)!;
      d += 1;
    }
    return d;
  };

  const linesBySpan = useMemo(() => {
    const m = new Map<string, AppLogLine[]>();
    lines.forEach((l) => m.set(l.span_id, [...(m.get(l.span_id) ?? []), l]));
    return m;
  }, [lines]);

  return (
    <div className="fixed inset-0 z-20 flex justify-end bg-black/50" onClick={onClose}>
      <div
        className="h-full w-full max-w-4xl overflow-y-auto border-l border-[var(--border)] bg-[var(--panel)] p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <h2 className="flex items-center gap-2 text-base font-semibold">
              <GitBranch className="h-4 w-4 text-[var(--accent)]" />
              {trace.method} {trace.path || trace.route}
            </h2>
            <p className="mt-1 break-all font-mono text-[10px] text-[var(--muted)]">{trace.trace_id}</p>
          </div>
          <button onClick={onClose} className="rounded p-1 text-[var(--muted)] hover:text-[var(--text)]">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="wall clock" value={`${(span).toFixed(0)}ms`} />
          <Stat label="hops" value={String(trace.spans)} icon={<Layers className="h-3 w-3" />} />
          <Stat label="services" value={String(trace.services)} />
          <Stat
            label="log lines"
            value={trace.log_lines < 0 ? '—' : String(trace.log_lines)}
            icon={<ScrollText className="h-3 w-3" />}
          />
        </div>

        {err && <div className="text-xs text-[var(--bad)]">{err}</div>}
        {!hops && !err && <div className="text-xs text-[var(--muted)]">loading…</div>}

        {hops?.length === 1 && (
          <p className="mb-3 rounded-lg border border-[var(--border)] p-3 text-[11px] text-[var(--muted)]">
            Only one hop reported. The services this one called are not instrumented — add an
            OpticTrace SDK or sidecar to them and they appear on this timeline, nested under
            this span.
          </p>
        )}

        {/* Ordered by when each hop STARTED, so the root leads and the calls it
            made nest under it. fetchTrace sorts by the stored time, which is
            when each finished — the exact inversion this page exists to show
            correctly. */}
        <div className="space-y-2">
          {[...(hops ?? [])].sort((a, b) => startOf(a) - startOf(b)).map((h) => {
            const start = startOf(h);
            const left = ((start - t0) / span) * 100;
            const width = Math.max(0.8, (h.duration_ms / span) * 100);
            const hopLines = linesBySpan.get(h.span_id ?? '') ?? [];
            return (
              <div key={h.id} className="rounded-lg border border-[var(--border)]/70 p-2.5">
                <div
                  className="flex items-center gap-2 text-xs"
                  style={{ paddingLeft: `${depthOf(h) * 14}px` }}
                >
                  <MethodBadge method={h.method} />
                  <span className="max-w-[14rem] flex-1 truncate font-mono text-[11px]">{h.path}</span>
                  <span className="w-20 shrink-0 truncate text-[10px] text-[var(--muted)]">{h.service}</span>
                  <StatusBadge status={h.status} />
                  <span className="w-16 shrink-0 text-right tabular-nums text-[var(--muted)]">
                    {h.duration_ms.toFixed(1)}ms
                  </span>
                </div>
                <div className="relative mt-1.5 h-2 overflow-hidden rounded bg-[var(--border)]/50">
                  <div
                    className={`absolute h-full rounded ${
                      h.status >= 500 ? 'bg-[var(--bad)]' : h.status >= 400 ? 'bg-[var(--warn)]' : 'bg-[var(--accent)]'
                    }`}
                    style={{ left: `${left}%`, width: `${width}%` }}
                    title={`+${(start - t0).toFixed(0)}ms → +${(start - t0 + h.duration_ms).toFixed(0)}ms`}
                  />
                </div>
                {hopLines.length > 0 && (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-[10px] text-[var(--muted)] hover:text-[var(--text)]">
                      {hopLines.length} log line{hopLines.length === 1 ? '' : 's'}
                    </summary>
                    <div className="mt-1.5 space-y-0.5 font-mono text-[10px]">
                      {hopLines.map((l) => (
                        <div key={l.id} className="flex gap-2">
                          <span className="w-14 shrink-0 text-right text-[var(--muted)]">
                            {relative(new Date(l.time).getTime() - t0)}
                          </span>
                          <span className={`w-10 shrink-0 uppercase ${levelTone(l.level)}`}>{l.level}</span>
                          <span className="min-w-0 flex-1 break-all">{l.message}</span>
                        </div>
                      ))}
                    </div>
                  </details>
                )}
              </div>
            );
          })}
        </div>

        <Link
          href={`/inspector?trace=${encodeURIComponent(trace.trace_id)}`}
          className="mt-4 inline-block text-xs text-[var(--accent)] hover:underline"
        >
          Open these hops in the Inspector, with payloads →
        </Link>
      </div>
    </div>
  );
}

/** Offset from the start of the trace.
 *
 *  A line can land microseconds before the derived start — the hop's duration
 *  is measured to a finer resolution than the record's timestamp — so the sign
 *  is rendered rather than assumed. "+-1ms" reads as a bug; "-1ms" reads as a
 *  clock. */
function relative(ms: number) {
  return `${ms < 0 ? '' : '+'}${ms.toFixed(0)}ms`;
}

function Stat({ label, value, icon }: { label: string; value: string; icon?: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-[var(--border)] p-2.5">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-[var(--muted)]">
        {icon}
        {label}
      </div>
      <div className="mt-0.5 tabular-nums">{value}</div>
    </div>
  );
}

function levelTone(level: string) {
  switch (level) {
    case 'error':
    case 'fatal':
      return 'text-[var(--bad)]';
    case 'warn':
      return 'text-[var(--warn)]';
    case 'debug':
    case 'trace':
      return 'text-[var(--muted)]';
    default:
      return 'text-[var(--good)]';
  }
}

'use client';

import { Suspense, useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { ChevronLeft, ChevronRight, GitBranch, RefreshCw, Search } from 'lucide-react';
import { fetchAppLogs, fetchAppLogStats, type AppLogLine, type AppLogSummary } from '@/lib/api';

const PAGE_SIZE = 100;
const LEVELS: [string, string][] = [
  ['', 'Every level'],
  ['debug', 'debug and up'],
  ['info', 'info and up'],
  ['warn', 'warn and up'],
  ['error', 'errors only'],
];
const WINDOWS: [string, string][] = [
  ['15m', 'Last 15m'],
  ['1h', 'Last 1h'],
  ['6h', 'Last 6h'],
  ['24h', 'Last 24h'],
];

export default function LogsPage() {
  return (
    <Suspense fallback={<div className="text-sm text-[var(--muted)]">loading…</div>}>
      <Logs />
    </Suspense>
  );
}

/** Application logs, across requests.
 *
 *  Until now these were reachable only from a record you had already found,
 *  which is backwards: the log line is usually what you have — someone pasted
 *  it — and the request is what you are trying to find. Every line here links
 *  back to the exchange that produced it, by span id, which is a fact rather
 *  than a timestamp guess. */
function Logs() {
  const [lines, setLines] = useState<AppLogLine[]>([]);
  const [total, setTotal] = useState(0);
  const [supported, setSupported] = useState(true);
  const [summary, setSummary] = useState<AppLogSummary | null>(null);
  const [page, setPage] = useState(0);
  const [q, setQ] = useState('');
  const [level, setLevel] = useState('');
  const [service, setService] = useState('');
  const [win, setWin] = useState('1h');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [res, sum] = await Promise.all([
        fetchAppLogs({ window: win, level, service, q, limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
        fetchAppLogStats(win).catch(() => null),
      ]);
      setLines(res.lines);
      setTotal(res.total);
      setSupported(res.supported);
      setSummary(sum);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [win, level, service, q, page]);

  useEffect(() => {
    const t = setTimeout(load, 250); // debounce typing
    return () => clearTimeout(t);
  }, [load]);

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const services = Object.keys(summary?.by_service ?? {}).sort();

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Application logs</h1>
          <p className="text-xs text-[var(--muted)]">
            {total.toLocaleString()} line{total === 1 ? '' : 's'}
            {summary ? ` from ${summary.spans_with_logs.toLocaleString()} requests` : ''} · last {win}
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-1.5 rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {!supported && (
        <div className="panel p-6 text-sm text-[var(--muted)]">
          <p className="mb-2 text-[var(--text)]">Application logs are not enabled.</p>
          <p className="max-w-2xl text-xs">
            Turn on <code className="font-mono text-[var(--text)]">telemetry.app_logs</code> in{' '}
            <Link href="/config" className="text-[var(--accent)] hover:underline">
              optic.yaml
            </Link>
            , then ship lines with an SDK log handler or collect a process&apos;s output with{' '}
            <code className="font-mono text-[var(--text)]">optictrace run -exec</code>. Lines are
            governed by the same policy as payloads before anything is stored.
          </p>
        </div>
      )}

      {supported && (
        <>
          {/* Level counts double as filters: the fastest route to "show me the
              errors" is clicking the number that says how many there are. */}
          {summary && summary.total > 0 && (
            <div className="flex flex-wrap gap-2">
              {['error', 'warn', 'info', 'debug'].map((lv) => {
                const n = summary.by_level[lv] ?? 0;
                if (!n) return null;
                return (
                  <button
                    key={lv}
                    onClick={() => {
                      setLevel(level === lv ? '' : lv);
                      setPage(0);
                    }}
                    className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                      level === lv ? levelActive(lv) : `border-[var(--border)] ${levelTone(lv)}`
                    }`}
                  >
                    {lv} · {n.toLocaleString()}
                  </button>
                );
              })}
            </div>
          )}

          <div className="panel flex flex-wrap items-center gap-2 p-3">
            <div className="relative min-w-56 flex-1">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[var(--muted)]" />
              <input
                value={q}
                onChange={(e) => {
                  setQ(e.target.value);
                  setPage(0);
                }}
                placeholder="Search message text…"
                className="w-full rounded-lg border border-[var(--border)] bg-transparent py-1.5 pl-8 pr-3 text-sm outline-none focus:border-[var(--accent)]/60"
              />
            </div>
            <Select value={level} onChange={(v) => { setLevel(v); setPage(0); }} options={LEVELS} />
            <Select
              value={service}
              onChange={(v) => { setService(v); setPage(0); }}
              options={[['', 'Every service'], ...services.map((s) => [s, s] as [string, string])]}
            />
            <Select value={win} onChange={(v) => { setWin(v); setPage(0); }} options={WINDOWS} />
          </div>

          {error && <div className="panel border-[var(--bad)]/40 p-3 text-xs text-[var(--bad)]">{error}</div>}

          <div className="panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <tbody className="font-mono text-xs">
                  {lines.map((l) => (
                    <tr key={l.id} className="border-t border-[var(--border)]/50 align-top hover:bg-white/[.03]">
                      <td className="whitespace-nowrap px-3 py-1.5 text-[var(--muted)]">
                        {new Date(l.time).toLocaleTimeString([], { hour12: false })}
                        <span className="opacity-60">
                          .{String(new Date(l.time).getMilliseconds()).padStart(3, '0')}
                        </span>
                      </td>
                      <td className={`whitespace-nowrap px-2 py-1.5 uppercase ${levelTone(l.level)}`}>{l.level}</td>
                      <td className="whitespace-nowrap px-2 py-1.5 text-[var(--muted)]">{l.service}</td>
                      <td className="w-full px-2 py-1.5 break-all">
                        {l.message}
                        {l.truncated && <span className="ml-1 text-[10px] text-[var(--warn)]">[truncated]</span>}
                        {l.fields && Object.keys(l.fields).length > 0 && (
                          <span className="ml-2 text-[10px] text-[var(--muted)]">
                            {Object.entries(l.fields).map(([k, v]) => `${k}=${v}`).join(' ')}
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5">
                        {/* The span is what ties this line to a request, as a
                            fact. Timestamp matching would file one tenant's
                            line inside another tenant's call under load. */}
                        {l.trace_id ? (
                          <Link
                            href={`/inspector?trace=${encodeURIComponent(l.trace_id)}`}
                            className="flex items-center gap-1 text-[var(--accent)] hover:underline"
                          >
                            <GitBranch className="h-3 w-3" /> request
                          </Link>
                        ) : (
                          <span className="text-[var(--muted)]" title="Logged with no request in flight">
                            —
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {lines.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-4 py-10 text-center text-[var(--muted)]">
                        No log lines match.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="flex items-center justify-between text-xs text-[var(--muted)]">
            <span>
              Page {page + 1} of {pages}
            </span>
            <div className="flex gap-1">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="rounded border border-[var(--border)] p-1.5 disabled:opacity-40"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(pages - 1, p + 1))}
                disabled={page >= pages - 1}
                className="rounded border border-[var(--border)] p-1.5 disabled:opacity-40"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Select({
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
      className="rounded-lg border border-[var(--border)] bg-transparent px-2 py-1.5 text-sm outline-none focus:border-[var(--accent)]/60"
    >
      {options.map(([v, label]) => (
        <option key={v} value={v} className="bg-[var(--panel)]">
          {label}
        </option>
      ))}
    </select>
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

function levelActive(level: string) {
  switch (level) {
    case 'error':
      return 'border-[var(--bad)]/50 bg-[var(--bad)]/10 text-[var(--bad)]';
    case 'warn':
      return 'border-[var(--warn)]/50 bg-[var(--warn)]/10 text-[var(--warn)]';
    case 'debug':
      return 'border-[var(--border)] bg-white/5 text-[var(--text)]';
    default:
      return 'border-[var(--good)]/50 bg-[var(--good)]/10 text-[var(--good)]';
  }
}

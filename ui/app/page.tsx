'use client';

import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ArrowDownUp, Clock3, Zap } from 'lucide-react';
import { fetchStats, type Stats } from '@/lib/api';
import { TrafficChart, LatencyChart } from '@/components/charts';
import { MethodBadge } from '@/components/badges';

const WINDOWS = [
  { label: '15m', window: '15m', bucket: '30s' },
  { label: '1h', window: '1h', bucket: '1m' },
  { label: '6h', window: '6h', bucket: '5m' },
  { label: '24h', window: '24h', bucket: '30m' },
];

export default function Overview() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [win, setWin] = useState(WINDOWS[1]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setStats(await fetchStats(win.window, win.bucket));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [win]);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000); // live: refresh every 5s
    return () => clearInterval(t);
  }, [load]);

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Overview</h1>
        <div className="flex gap-1 rounded-lg border border-[var(--border)] p-1">
          {WINDOWS.map((w) => (
            <button
              key={w.label}
              onClick={() => setWin(w)}
              className={`rounded-md px-3 py-1 text-xs ${
                win.label === w.label
                  ? 'bg-[var(--accent)]/15 text-[var(--accent)]'
                  : 'text-[var(--muted)] hover:text-[var(--text)]'
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="panel border-[var(--bad)]/40 p-4 text-sm text-[var(--bad)]">
          Cannot reach the OpticTrace agent: {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard icon={ArrowDownUp} label="Requests" value={stats ? fmtCount(stats.total) : '—'} />
        <StatCard
          icon={AlertTriangle}
          label="Error rate"
          value={stats ? `${(stats.error_rate * 100).toFixed(2)}%` : '—'}
          tone={stats && stats.error_rate > 0.05 ? 'bad' : stats && stats.error_rate > 0.01 ? 'warn' : 'good'}
        />
        <StatCard icon={Clock3} label="P95 latency" value={stats ? fmtMs(stats.p95_latency_ms) : '—'} />
        <StatCard icon={Zap} label="P99 latency" value={stats ? fmtMs(stats.p99_latency_ms) : '—'} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-medium text-[var(--muted)]">Request volume & errors</h2>
          <TrafficChart series={stats?.series ?? []} />
        </div>
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-medium text-[var(--muted)]">Average latency</h2>
          <LatencyChart series={stats?.series ?? []} />
        </div>
      </div>

      <div className="panel overflow-hidden">
        <h2 className="border-b border-[var(--border)] px-4 py-3 text-sm font-medium text-[var(--muted)]">
          Top routes
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-[var(--muted)]">
                <th className="px-4 py-2 font-medium">Route</th>
                <th className="px-4 py-2 font-medium">Method</th>
                <th className="px-4 py-2 text-right font-medium">Requests</th>
                <th className="px-4 py-2 text-right font-medium">Errors</th>
                <th className="px-4 py-2 text-right font-medium">Avg</th>
                <th className="px-4 py-2 text-right font-medium">P95</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.top_routes ?? []).map((r) => (
                <tr key={`${r.method}-${r.route}`} className="border-t border-[var(--border)]/60">
                  <td className="px-4 py-2 font-mono text-xs">{r.route}</td>
                  <td className="px-4 py-2">
                    <MethodBadge method={r.method} />
                  </td>
                  <td className="px-4 py-2 text-right">{fmtCount(r.count)}</td>
                  <td className={`px-4 py-2 text-right ${r.errors > 0 ? 'text-[var(--bad)]' : ''}`}>
                    {fmtCount(r.errors)}
                  </td>
                  <td className="px-4 py-2 text-right">{fmtMs(r.avg_latency_ms)}</td>
                  <td className="px-4 py-2 text-right">{fmtMs(r.p95_latency_ms)}</td>
                </tr>
              ))}
              {!stats?.top_routes?.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-[var(--muted)]">
                    No traffic in this window yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {stats && Object.keys(stats.status_counts).length > 0 && (
        <div className="flex flex-wrap gap-3">
          {Object.entries(stats.status_counts)
            .sort()
            .map(([cls, n]) => (
              <span
                key={cls}
                className={`rounded-full border px-3 py-1 text-xs ${classTone(cls)}`}
              >
                {cls}: {fmtCount(n)}
              </span>
            ))}
        </div>
      )}
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  tone?: 'good' | 'warn' | 'bad';
}) {
  const toneColor =
    tone === 'bad' ? 'text-[var(--bad)]' : tone === 'warn' ? 'text-[var(--warn)]' : 'text-[var(--text)]';
  return (
    <div className="panel p-4">
      <div className="flex items-center gap-2 text-xs text-[var(--muted)]">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div className={`mt-2 text-2xl font-semibold ${toneColor}`}>{value}</div>
    </div>
  );
}

const fmtCount = (n: number) => Intl.NumberFormat().format(n);
const fmtMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(1)}ms`);

function classTone(cls: string) {
  if (cls.startsWith('5')) return 'border-[var(--bad)]/40 text-[var(--bad)]';
  if (cls.startsWith('4')) return 'border-[var(--warn)]/40 text-[var(--warn)]';
  return 'border-[var(--good)]/40 text-[var(--good)]';
}

'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowDown, ArrowUp } from 'lucide-react';
import { fetchRoutes, type RouteDetail } from '@/lib/api';
import { MethodBadge } from '@/components/badges';

const WINDOWS = ['15m', '1h', '6h', '24h'];
type SortKey = 'count' | 'errors' | 'avg_latency_ms' | 'p95_latency_ms' | 'p99_latency_ms';

export default function RoutesPage() {
  const [routes, setRoutes] = useState<RouteDetail[]>([]);
  const [win, setWin] = useState('1h');
  const [sortKey, setSortKey] = useState<SortKey>('count');
  const [desc, setDesc] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setRoutes((await fetchRoutes(win)).routes);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [win]);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  const sorted = useMemo(() => {
    const list = [...routes].sort((a, b) => (a[sortKey] - b[sortKey]) * (desc ? -1 : 1));
    return list;
  }, [routes, sortKey, desc]);

  const maxCount = Math.max(1, ...routes.map((r) => r.count));

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setDesc(!desc);
    else {
      setSortKey(key);
      setDesc(true);
    }
  };

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Routes</h1>
        <div className="flex gap-1 rounded-lg border border-[var(--border)] p-1">
          {WINDOWS.map((w) => (
            <button
              key={w}
              onClick={() => setWin(w)}
              className={`rounded-md px-3 py-1 text-xs ${
                win === w ? 'bg-[var(--accent)]/15 text-[var(--accent)]' : 'text-[var(--muted)] hover:text-[var(--text)]'
              }`}
            >
              {w}
            </button>
          ))}
        </div>
      </div>

      {error && <div className="panel border-[var(--bad)]/40 p-4 text-sm text-[var(--bad)]">{error}</div>}

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-[var(--muted)]">
                <th className="px-4 py-2.5 font-medium">Route</th>
                <th className="px-3 py-2.5 font-medium">Method</th>
                <SortHeader label="Requests" k="count" cur={sortKey} desc={desc} onClick={toggleSort} />
                <SortHeader label="Errors" k="errors" cur={sortKey} desc={desc} onClick={toggleSort} />
                <SortHeader label="Avg" k="avg_latency_ms" cur={sortKey} desc={desc} onClick={toggleSort} />
                <th className="px-3 py-2.5 text-right font-medium">P50</th>
                <SortHeader label="P95" k="p95_latency_ms" cur={sortKey} desc={desc} onClick={toggleSort} />
                <SortHeader label="P99" k="p99_latency_ms" cur={sortKey} desc={desc} onClick={toggleSort} />
                <th className="px-3 py-2.5 text-right font-medium">Traffic</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((r) => {
                const errPct = r.count ? (r.errors / r.count) * 100 : 0;
                return (
                  <tr key={`${r.method}-${r.route}`} className="border-t border-[var(--border)]/60">
                    <td className="px-4 py-2">
                      <div className="font-mono text-xs">{r.route}</div>
                      <div className="mt-1 h-1 max-w-48 overflow-hidden rounded bg-white/5">
                        <div
                          className="h-full rounded bg-[var(--accent)]/60"
                          style={{ width: `${(r.count / maxCount) * 100}%` }}
                        />
                      </div>
                    </td>
                    <td className="px-3 py-2"><MethodBadge method={r.method} /></td>
                    <td className="px-3 py-2 text-right">{fmt(r.count)}</td>
                    <td className={`px-3 py-2 text-right ${errPct > 5 ? 'text-[var(--bad)]' : errPct > 0 ? 'text-[var(--warn)]' : ''}`}>
                      {fmt(r.errors)}{r.errors > 0 && <span className="text-[10px] text-[var(--muted)]"> ({errPct.toFixed(1)}%)</span>}
                    </td>
                    <td className="px-3 py-2 text-right">{ms(r.avg_latency_ms)}</td>
                    <td className="px-3 py-2 text-right">{ms(r.p50_latency_ms)}</td>
                    <td className="px-3 py-2 text-right">{ms(r.p95_latency_ms)}</td>
                    <td className="px-3 py-2 text-right">{ms(r.p99_latency_ms)}</td>
                    <td className="px-3 py-2 text-right text-xs text-[var(--muted)]">
                      {bytes(r.req_bytes)} ↑ {bytes(r.resp_bytes)} ↓
                    </td>
                  </tr>
                );
              })}
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-10 text-center text-[var(--muted)]">
                    No traffic in this window yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function SortHeader({
  label, k, cur, desc, onClick,
}: {
  label: string; k: SortKey; cur: SortKey; desc: boolean; onClick: (k: SortKey) => void;
}) {
  const active = cur === k;
  return (
    <th
      onClick={() => onClick(k)}
      className={`cursor-pointer select-none px-3 py-2.5 text-right font-medium hover:text-[var(--text)] ${
        active ? 'text-[var(--accent)]' : ''
      }`}
    >
      <span className="inline-flex items-center gap-0.5">
        {label}
        {active && (desc ? <ArrowDown className="h-3 w-3" /> : <ArrowUp className="h-3 w-3" />)}
      </span>
    </th>
  );
}

const fmt = (n: number) => Intl.NumberFormat().format(n);
const ms = (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(2)}s` : `${v.toFixed(1)}ms`);
function bytes(n: number) {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)}MB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)}KB`;
  return `${n}B`;
}

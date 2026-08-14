'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Coins, Download } from 'lucide-react';
import { fetchUsage, usageCsvUrl, type UsageResponse } from '@/lib/api';

const WINDOWS = ['1h', '6h', '24h', '168h'];
const WINDOW_LABELS: Record<string, string> = { '1h': '1h', '6h': '6h', '24h': '24h', '168h': '7d' };

export default function UsagePage() {
  const [data, setData] = useState<UsageResponse | null>(null);
  const [win, setWin] = useState('24h');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await fetchUsage(win));
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

  const meterNames = useMemo(() => {
    const names = new Set<string>();
    data?.consumers.forEach((c) => Object.keys(c.meters ?? {}).forEach((n) => names.add(n)));
    return [...names].sort();
  }, [data]);

  const totals = useMemo(() => {
    const t = { requests: 0, bytes: 0, cost: 0 };
    data?.consumers.forEach((c) => {
      t.requests += c.requests;
      t.bytes += c.req_bytes + c.resp_bytes;
      t.cost += c.cost?.total ?? 0;
    });
    return t;
  }, [data]);

  const maxRequests = Math.max(1, ...(data?.consumers ?? []).map((c) => c.requests));

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <Coins className="h-5 w-5 text-[var(--accent)]" /> Usage & Cost
        </h1>
        <div className="flex items-center gap-2">
          <a
            href={usageCsvUrl(win)}
            download
            className="flex items-center gap-1.5 rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)]"
          >
            <Download className="h-3.5 w-3.5" /> Billing CSV
          </a>
          <div className="flex gap-1 rounded-lg border border-[var(--border)] p-1">
            {WINDOWS.map((w) => (
              <button
                key={w}
                onClick={() => setWin(w)}
                className={`rounded-md px-3 py-1 text-xs ${
                  win === w ? 'bg-[var(--accent)]/15 text-[var(--accent)]' : 'text-[var(--muted)] hover:text-[var(--text)]'
                }`}
              >
                {WINDOW_LABELS[w]}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && <div className="panel border-[var(--bad)]/40 p-4 text-sm text-[var(--bad)]">{error}</div>}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card label={`Consumers (by ${data?.label ?? 'tenant'})`} value={String(data?.consumers.length ?? 0)} />
        <Card label="Requests" value={fmt(totals.requests)} />
        <Card label="Data transferred" value={bytes(totals.bytes)} />
        <Card
          label="Estimated cost"
          value={data?.billing ? money(totals.cost, data.currency) : '—'}
          sub={data?.billing ? undefined : 'add telemetry.billing to optic.yaml'}
        />
      </div>

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-[var(--muted)]">
                <th className="px-4 py-2.5 font-medium">Consumer</th>
                <th className="px-3 py-2.5 text-right font-medium">Requests</th>
                <th className="px-3 py-2.5 text-right font-medium">Errors</th>
                <th className="px-3 py-2.5 text-right font-medium">Data</th>
                <th className="px-3 py-2.5 text-right font-medium">Compute</th>
                {meterNames.map((m) => (
                  <th key={m} className="px-3 py-2.5 text-right font-medium capitalize">{m}</th>
                ))}
                {data?.billing && <th className="px-3 py-2.5 text-right font-medium">Cost</th>}
              </tr>
            </thead>
            <tbody>
              {(data?.consumers ?? []).map((c) => (
                <tr key={c.consumer} className="border-t border-[var(--border)]/60">
                  <td className="px-4 py-2">
                    <div className={c.consumer === '(unattributed)' ? 'text-[var(--muted)]' : 'font-medium'}>
                      {c.consumer}
                    </div>
                    <div className="mt-1 h-1 max-w-40 overflow-hidden rounded bg-white/5">
                      <div
                        className="h-full rounded bg-[var(--accent)]/60"
                        style={{ width: `${(c.requests / maxRequests) * 100}%` }}
                      />
                    </div>
                  </td>
                  <td className="px-3 py-2 text-right">{fmt(c.requests)}</td>
                  <td className={`px-3 py-2 text-right ${c.errors > 0 ? 'text-[var(--bad)]' : ''}`}>{fmt(c.errors)}</td>
                  <td className="px-3 py-2 text-right">{bytes(c.req_bytes + c.resp_bytes)}</td>
                  <td className="px-3 py-2 text-right">{compute(c.duration_ms_total)}</td>
                  {meterNames.map((m) => (
                    <td key={m} className="px-3 py-2 text-right">
                      {c.meters?.[m] !== undefined ? fmt(Math.round(c.meters[m])) : '—'}
                    </td>
                  ))}
                  {data?.billing && (
                    <td className="px-3 py-2 text-right font-medium" title={costBreakdown(c.cost)}>
                      {money(c.cost?.total ?? 0, data.currency)}
                    </td>
                  )}
                </tr>
              ))}
              {!data?.consumers.length && (
                <tr>
                  <td colSpan={6 + meterNames.length} className="px-4 py-10 text-center text-[var(--muted)]">
                    No attributed traffic in this window.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <p className="text-xs text-[var(--muted)]">
        Consumers are grouped by the <code className="text-[var(--accent)]">{data?.label ?? 'tenant'}</code> label
        extracted by your optic.yaml rules. Meters (e.g. LLM tokens) come from rule-level{' '}
        <code className="text-[var(--accent)]">meter</code> paths and work even on routes whose payload capture is
        restricted. Hover a cost for its component breakdown.
      </p>
    </div>
  );
}

function Card({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="panel p-4">
      <div className="text-xs text-[var(--muted)]">{label}</div>
      <div className="mt-1.5 text-2xl font-semibold">{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-[var(--muted)]">{sub}</div>}
    </div>
  );
}

const fmt = (n: number) => Intl.NumberFormat().format(n);

function bytes(n: number) {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(2)}GB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)}MB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)}KB`;
  return `${n}B`;
}

function compute(ms: number) {
  if (ms >= 60000) return `${(ms / 60000).toFixed(1)}min`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  return `${ms.toFixed(0)}ms`;
}

function money(v: number, currency: string) {
  return new Intl.NumberFormat(undefined, {
    style: 'currency',
    currency,
    maximumFractionDigits: v < 1 ? 6 : 2,
  }).format(v);
}

function costBreakdown(cost?: Record<string, number>) {
  if (!cost) return '';
  return Object.entries(cost)
    .filter(([k]) => k !== 'total')
    .map(([k, v]) => `${k}: ${v.toFixed(6)}`)
    .join('\n');
}

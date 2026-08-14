'use client';

import { useCallback, useEffect, useState } from 'react';
import { Database, PlugZap, Server } from 'lucide-react';
import { fetchSystem, type SystemInfo, API_BASE } from '@/lib/api';

export default function SystemPage() {
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setInfo(await fetchSystem());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <Server className="h-5 w-5 text-[var(--accent)]" /> System
      </h1>

      {error && <div className="panel border-[var(--bad)]/40 p-4 text-sm text-[var(--bad)]">{error}</div>}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-medium text-[var(--muted)]">Agent</h2>
          <KV k="Service" v={info?.service ?? '—'} />
          <KV k="Version" v={info?.version ?? '—'} />
          <KV k="Uptime" v={info ? uptime(info.uptime_seconds) : '—'} />
          <KV k="Upstream" v={info?.upstream || '(embedded mode)'} />
          <KV k="Config" v={info?.config_path ?? '—'} />
          <KV k="Rules" v={info ? String(info.rules ?? 0) : '—'} />
        </div>

        <div className="panel p-4">
          <h2 className="mb-3 flex items-center gap-1.5 text-sm font-medium text-[var(--muted)]">
            <Database className="h-3.5 w-3.5" /> Payload store
          </h2>
          {info?.store.enabled ? (
            <>
              <KV k="Status" v="enabled (SQLite)" />
              <KV k="Records" v={fmt(info.store.records ?? 0)} />
            </>
          ) : (
            <p className="text-sm text-[var(--muted)]">Disabled (telemetry.store.driver: none).</p>
          )}
          <div className="mt-3 border-t border-[var(--border)]/60 pt-3 text-xs text-[var(--muted)]">
            Raw metrics: <a className="text-[var(--accent)]" href={`${API_BASE}/metrics`} target="_blank" rel="noreferrer">/metrics</a>
          </div>
        </div>
      </div>

      <div className="panel overflow-hidden">
        <h2 className="flex items-center gap-1.5 border-b border-[var(--border)] px-4 py-3 text-sm font-medium text-[var(--muted)]">
          <PlugZap className="h-3.5 w-3.5" /> Output exporters
        </h2>
        {info && info.exporters.length > 0 ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-[var(--muted)]">
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 text-right font-medium">Delivered</th>
                <th className="px-3 py-2 text-right font-medium">Failed</th>
                <th className="px-3 py-2 text-right font-medium">Dropped</th>
                <th className="px-3 py-2 text-right font-medium">Queue</th>
                <th className="px-3 py-2 text-right font-medium">Health</th>
              </tr>
            </thead>
            <tbody>
              {info.exporters.map((e) => {
                const unhealthy = e.failed > 0 || e.dropped > 0;
                return (
                  <tr key={e.name} className="border-t border-[var(--border)]/60">
                    <td className="px-4 py-2 font-medium">{e.name}</td>
                    <td className="px-3 py-2">
                      <span className="rounded border border-[var(--border)] px-1.5 py-0.5 font-mono text-[10px]">{e.type}</span>
                    </td>
                    <td className="px-3 py-2 text-right">{fmt(e.delivered)}</td>
                    <td className={`px-3 py-2 text-right ${e.failed > 0 ? 'text-[var(--bad)]' : ''}`}>{fmt(e.failed)}</td>
                    <td className={`px-3 py-2 text-right ${e.dropped > 0 ? 'text-[var(--warn)]' : ''}`}>{fmt(e.dropped)}</td>
                    <td className="px-3 py-2 text-right">{e.queue_len}</td>
                    <td className="px-3 py-2 text-right">
                      <span className={unhealthy ? 'text-[var(--warn)]' : 'text-[var(--good)]'}>
                        {unhealthy ? '● degraded' : '● ok'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <p className="px-4 py-8 text-center text-sm text-[var(--muted)]">
            No exporters configured. Add <code className="text-[var(--accent)]">telemetry.exporters</code> to
            optic.yaml to ship governed records to files, webhooks, or your own plugin executable.
          </p>
        )}
      </div>
    </div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-2 border-b border-[var(--border)]/40 py-1.5 text-sm last:border-0">
      <span className="text-[var(--muted)]">{k}</span>
      <span className="truncate font-mono text-xs leading-5">{v}</span>
    </div>
  );
}

const fmt = (n: number) => Intl.NumberFormat().format(n);

function uptime(s: number) {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  const h = Math.floor(s / 3600);
  if (h < 24) return `${h}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

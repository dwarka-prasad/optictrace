'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  ArrowDownUp,
  Clock3,
  FileText,
  Layers,
  ShieldCheck,
  Users,
  Zap,
} from 'lucide-react';
import {
  fetchAppLogStats,
  fetchRuleStats,
  fetchServices,
  fetchStats,
  fetchUsage,
  type AppLogSummary,
  type RuleView,
  type ServiceStat,
  type Stats,
  type UsageResponse,
} from '@/lib/api';
import { BarList, LatencyChart, StatusMixChart, TrafficChart } from '@/components/charts';
import { MethodBadge } from '@/components/badges';

const WINDOWS = [
  { label: '15m', window: '15m', bucket: '30s' },
  { label: '1h', window: '1h', bucket: '1m' },
  { label: '6h', window: '6h', bucket: '5m' },
  { label: '24h', window: '24h', bucket: '30m' },
];

export default function Overview() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [rules, setRules] = useState<RuleView[]>([]);
  const [services, setServices] = useState<ServiceStat[]>([]);
  const [usage, setUsage] = useState<UsageResponse | null>(null);
  const [logs, setLogs] = useState<AppLogSummary | null>(null);
  const [win, setWin] = useState(WINDOWS[1]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      // One window, one refresh: panels that reload independently show
      // numbers from different moments and quietly disagree with each other.
      const [s, r, sv, u, l] = await Promise.all([
        fetchStats(win.window, win.bucket),
        fetchRuleStats(win.window).catch(() => ({ rules: [], window_total: 0 })),
        fetchServices(win.window).catch(() => ({ services: [] })),
        fetchUsage(win.window).catch(() => null),
        fetchAppLogStats(win.window).catch(() => null),
      ]);
      setStats(s);
      setRules(r.rules ?? []);
      setServices(sv.services ?? []);
      setUsage(u);
      setLogs(l);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [win]);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  // Governance coverage: the share of traffic a rule actually applied to.
  // This is the number that distinguishes this tool from an APM, so it belongs
  // above the latency charts rather than three pages in.
  const firing = rules.filter((r) => r.matches > 0);
  const silent = rules.filter((r) => r.matches === 0);
  const redacting = rules.reduce((n, r) => n + r.redact_headers + r.redact_json_fields, 0);
  // Deliberately NOT a "% of traffic governed" figure here. One request can
  // match several rules, so summing match counts over the request total
  // overstates coverage — and a governance number that flatters itself is
  // worse than no number. `optictrace review` computes real coverage by
  // walking records; this card reports what it can actually count.

  const errorLines = (logs?.by_level?.error ?? 0) + (logs?.by_level?.fatal ?? 0);
  const consumers = (usage?.consumers ?? []).filter((c) => c.consumer !== '(unattributed)');

  return (
    <div className="mx-auto max-w-7xl space-y-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Overview</h1>
          <p className="text-xs text-[var(--muted)]">
            Governed traffic across {services.length || 1} service
            {services.length === 1 ? '' : 's'} · last {win.label}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-xs text-[var(--muted)]">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[var(--good)] opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[var(--good)]" />
            </span>
            live
          </span>
          <div className="flex gap-1 rounded-lg border border-[var(--border)] p-1">
            {WINDOWS.map((w) => (
              <button
                key={w.label}
                onClick={() => setWin(w)}
                className={`rounded-md px-3 py-1 text-xs transition-colors ${
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
      </header>

      {error && (
        <div className="panel border-[var(--bad)]/40 p-4 text-sm text-[var(--bad)]">
          Cannot reach the OpticTrace agent: {error}
        </div>
      )}

      {/* Traffic health and governance posture, side by side. Both are the
          headline: a fast API that leaks is not a healthy one. */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <StatCard icon={ArrowDownUp} label="Requests" value={stats ? fmtCount(stats.total) : '—'} />
        <StatCard
          icon={AlertTriangle}
          label="Error rate"
          value={stats ? `${(stats.error_rate * 100).toFixed(2)}%` : '—'}
          tone={stats && stats.error_rate > 0.05 ? 'bad' : stats && stats.error_rate > 0.01 ? 'warn' : 'good'}
        />
        <StatCard icon={Clock3} label="P95" value={stats ? fmtMs(stats.p95_latency_ms) : '—'} />
        <StatCard icon={Zap} label="P99" value={stats ? fmtMs(stats.p99_latency_ms) : '—'} />
        <StatCard
          icon={ShieldCheck}
          label="Rules firing"
          value={rules.length ? `${firing.length}/${rules.length}` : '—'}
          hint={silent.length ? `${silent.length} matched nothing` : 'all rules active'}
          tone={rules.length === 0 ? undefined : silent.length === 0 ? 'good' : 'warn'}
          href="/governance"
        />
        <StatCard
          icon={FileText}
          label="Log lines"
          value={logs ? fmtCount(logs.total) : '—'}
          hint={errorLines > 0 ? `${fmtCount(errorLines)} at error` : 'none at error'}
          tone={errorLines > 0 ? 'warn' : undefined}
          href="/inspector"
        />
      </div>

      {/* A rule that never fires is the failure nobody notices: the config
          looks right, the dashboard looks green, and nothing is being
          enforced. Surfaced here rather than buried on the rules page. */}
      {silent.length > 0 && stats && stats.total > 0 && (
        <Link
          href="/governance"
          className="panel flex items-center gap-3 border-[var(--warn)]/40 bg-[var(--warn)]/5 p-3 text-xs text-[var(--warn)] hover:border-[var(--warn)]"
        >
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>
            <strong>{silent.length}</strong> rule{silent.length === 1 ? '' : 's'} matched nothing in
            this window ({silent.map((r) => r.name).slice(0, 3).join(', ')}
            {silent.length > 3 ? '…' : ''}) — a rule that never fires protects nothing.
          </span>
        </Link>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="panel p-4 lg:col-span-2">
          <PanelTitle>Request volume &amp; errors</PanelTitle>
          <TrafficChart series={stats?.series ?? []} />
        </div>
        <div className="panel p-4">
          <PanelTitle>Succeeded vs failed</PanelTitle>
          <StatusMixChart series={stats?.series ?? []} />
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="panel p-4">
          <PanelTitle>Average latency</PanelTitle>
          <LatencyChart series={stats?.series ?? []} />
        </div>

        <div className="panel p-4">
          <PanelTitle>Traffic by tenant</PanelTitle>
          <BarList
            items={consumers
              .slice(0, 6)
              .map((c) => ({
                label: c.consumer,
                value: c.requests,
                hint: `${fmtCount(c.requests)}${c.errors ? ` · ${c.errors} err` : ''}`,
              }))}
          />
        </div>

        <div className="panel p-4">
          <PanelTitle>Application logs by level</PanelTitle>
          <BarList
            items={LEVELS.filter((l) => (logs?.by_level?.[l] ?? 0) > 0).map((l) => ({
              label: l,
              value: logs?.by_level?.[l] ?? 0,
            }))}
            tone={levelColor}
          />
          {logs && logs.spans_with_logs > 0 && (
            <p className="mt-3 border-t border-[var(--border)]/60 pt-2 text-xs text-[var(--muted)]">
              {fmtCount(logs.spans_with_logs)} request
              {logs.spans_with_logs === 1 ? '' : 's'} explained by their own log lines
            </p>
          )}
        </div>
      </div>

      {/* The fleet. Only worth a panel when there is more than one service
          reporting — otherwise it is a table with one row saying nothing. */}
      {services.length > 1 && (
        <div className="panel overflow-hidden">
          <PanelTitle className="border-b border-[var(--border)] px-4 py-3">
            <span className="flex items-center gap-2">
              <Layers className="h-3.5 w-3.5" /> Services
            </span>
          </PanelTitle>
          <div className="grid gap-px bg-[var(--border)]/60 sm:grid-cols-2 lg:grid-cols-4">
            {services.map((s) => (
              <div key={s.service} className="bg-[var(--panel)] p-4">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate font-medium">{s.service}</span>
                  <span className="shrink-0 rounded-full border border-[var(--border)] px-2 py-0.5 text-[10px] text-[var(--muted)]">
                    {s.sources}
                  </span>
                </div>
                <div className="mt-2 grid grid-cols-3 gap-2 text-xs">
                  <Metric label="req" value={fmtCount(s.requests)} />
                  <Metric
                    label="err"
                    value={`${(s.error_rate * 100).toFixed(1)}%`}
                    tone={s.error_rate > 0.05 ? 'bad' : s.error_rate > 0.01 ? 'warn' : undefined}
                  />
                  <Metric label="p95" value={fmtMs(s.p95_latency_ms)} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel overflow-hidden">
          <PanelTitle className="border-b border-[var(--border)] px-4 py-3">Top routes</PanelTitle>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-[var(--muted)]">
                  <th className="px-4 py-2 font-medium">Route</th>
                  <th className="px-4 py-2 font-medium">Method</th>
                  <th className="px-4 py-2 text-right font-medium">Req</th>
                  <th className="px-4 py-2 text-right font-medium">Err</th>
                  <th className="px-4 py-2 text-right font-medium">P95</th>
                </tr>
              </thead>
              <tbody>
                {(stats?.top_routes ?? []).map((r) => (
                  <tr key={`${r.method}-${r.route}`} className="border-t border-[var(--border)]/60">
                    <td className="max-w-[16rem] truncate px-4 py-2 font-mono text-xs">{r.route}</td>
                    <td className="px-4 py-2"><MethodBadge method={r.method} /></td>
                    <td className="px-4 py-2 text-right tabular-nums">{fmtCount(r.count)}</td>
                    <td className={`px-4 py-2 text-right tabular-nums ${r.errors > 0 ? 'text-[var(--bad)]' : ''}`}>
                      {fmtCount(r.errors)}
                    </td>
                    <td className="px-4 py-2 text-right tabular-nums">{fmtMs(r.p95_latency_ms)}</td>
                  </tr>
                ))}
                {!stats?.top_routes?.length && (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-[var(--muted)]">
                      No traffic in this window yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel overflow-hidden">
          <PanelTitle className="border-b border-[var(--border)] px-4 py-3">
            <span className="flex items-center gap-2">
              <ShieldCheck className="h-3.5 w-3.5" /> Governance in effect
            </span>
          </PanelTitle>
          <div className="space-y-3 p-4">
            <div className="grid grid-cols-3 gap-3">
              <Metric label="rules firing" value={`${firing.length}/${rules.length}`} />
              <Metric label="fields masked" value={String(redacting)} />
              <Metric
                label="consumers"
                value={String(consumers.length)}
                icon={<Users className="h-3 w-3" />}
              />
            </div>
            <BarList
              items={firing
                .sort((a, b) => b.matches - a.matches)
                .slice(0, 6)
                .map((r) => ({ label: r.name, value: r.matches }))}
            />
            <Link
              href="/governance"
              className="block pt-1 text-xs text-[var(--accent)] hover:underline"
            >
              Rule detail and coverage →
            </Link>
          </div>
        </div>
      </div>

      {stats && Object.keys(stats.status_counts).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(stats.status_counts)
            .sort()
            .map(([cls, n]) => (
              <span key={cls} className={`rounded-full border px-3 py-1 text-xs ${classTone(cls)}`}>
                {cls}: {fmtCount(n)}
              </span>
            ))}
        </div>
      )}
    </div>
  );
}

const LEVELS = ['debug', 'info', 'warn', 'error', 'fatal'];

function levelColor(level: string) {
  if (level === 'error' || level === 'fatal') return 'var(--bad)';
  if (level === 'warn') return 'var(--warn)';
  if (level === 'debug') return 'var(--muted)';
  return 'var(--good)';
}

function PanelTitle({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <h2 className={`text-sm font-medium text-[var(--muted)] ${className || 'mb-3'}`}>{children}</h2>
  );
}

function Metric({
  label,
  value,
  tone,
  icon,
}: {
  label: string;
  value: string;
  tone?: 'good' | 'warn' | 'bad';
  icon?: React.ReactNode;
}) {
  return (
    <div>
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-[var(--muted)]">
        {icon}
        {label}
      </div>
      <div className={`mt-0.5 tabular-nums ${toneClass(tone)}`}>{value}</div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  hint,
  tone,
  href,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
  hint?: string;
  tone?: 'good' | 'warn' | 'bad';
  href?: string;
}) {
  const body = (
    <>
      <div className="flex items-center gap-2 text-xs text-[var(--muted)]">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div className={`mt-2 text-2xl font-semibold tabular-nums ${toneClass(tone)}`}>{value}</div>
      {hint && <div className="mt-0.5 truncate text-[11px] text-[var(--muted)]">{hint}</div>}
    </>
  );
  const cls = 'panel p-4' + (href ? ' transition-colors hover:border-[var(--accent)]/50' : '');
  return href ? (
    <Link href={href} className={cls}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

function toneClass(tone?: 'good' | 'warn' | 'bad') {
  if (tone === 'bad') return 'text-[var(--bad)]';
  if (tone === 'warn') return 'text-[var(--warn)]';
  if (tone === 'good') return 'text-[var(--good)]';
  return 'text-[var(--text)]';
}

const fmtCount = (n: number) => Intl.NumberFormat().format(n);
const fmtMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${ms.toFixed(1)}ms`);

function classTone(cls: string) {
  if (cls.startsWith('5')) return 'border-[var(--bad)]/40 text-[var(--bad)]';
  if (cls.startsWith('4')) return 'border-[var(--warn)]/40 text-[var(--warn)]';
  return 'border-[var(--good)]/40 text-[var(--good)]';
}

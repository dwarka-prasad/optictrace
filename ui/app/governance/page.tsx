'use client';

import { useCallback, useEffect, useState } from 'react';
import { EyeOff, ShieldCheck, Tags, VenetianMask } from 'lucide-react';
import { fetchRuleStats, type RuleView } from '@/lib/api';
import { MethodBadge } from '@/components/badges';

const WINDOWS = ['15m', '1h', '6h', '24h'];

export default function GovernancePage() {
  const [rules, setRules] = useState<RuleView[]>([]);
  const [total, setTotal] = useState(0);
  const [win, setWin] = useState('1h');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetchRuleStats(win);
      setRules(res.rules);
      setTotal(res.window_total);
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

  const governed = rules.reduce((n, r) => n + r.matches, 0);
  const restricting = rules.filter((r) => (r.restrict?.length ?? 0) > 0);
  const redacting = rules.filter((r) => r.redact_headers + r.redact_json_fields > 0);

  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <ShieldCheck className="h-5 w-5 text-[var(--accent)]" /> Governance
        </h1>
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

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Card label="Requests in window" value={fmt(total)} />
        <Card label="Rule matches" value={fmt(governed)} sub={total ? `${Math.min(100, (governed / total) * 100).toFixed(0)}% of traffic governed` : undefined} />
        <Card label="Restriction rules" value={String(restricting.length)} sub="disable capture" />
        <Card label="Redaction rules" value={String(redacting.length)} sub="mask sensitive fields" />
      </div>

      <div className="panel overflow-hidden">
        <h2 className="border-b border-[var(--border)] px-4 py-3 text-sm font-medium text-[var(--muted)]">
          Rules (evaluated top-to-bottom, actions merge)
        </h2>
        <div className="divide-y divide-[var(--border)]/60">
          {rules.map((r) => (
            <div key={r.name} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <div className="min-w-56 flex-1">
                <div className="text-sm font-medium">{r.name}</div>
                <div className="mt-0.5 flex items-center gap-2 font-mono text-xs text-[var(--muted)]">
                  {r.path}
                  {(r.methods ?? []).map((m) => <MethodBadge key={m} method={m} />)}
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5 text-[11px]">
                {(r.restrict ?? []).map((f) => (
                  <Chip key={f} tone="warn" icon={EyeOff}>no {f.replace('_', ' ')}</Chip>
                ))}
                {r.redact_headers > 0 && (
                  <Chip tone="accent" icon={VenetianMask}>{r.redact_headers} header{r.redact_headers > 1 ? 's' : ''} redacted</Chip>
                )}
                {r.redact_json_fields > 0 && (
                  <Chip tone="accent" icon={VenetianMask}>{r.redact_json_fields} JSON path{r.redact_json_fields > 1 ? 's' : ''}</Chip>
                )}
                {r.labels > 0 && <Chip tone="good" icon={Tags}>{r.labels} label{r.labels > 1 ? 's' : ''}</Chip>}
                {r.sample !== undefined && r.sample !== null && (
                  <Chip tone="muted">sample {(r.sample * 100).toFixed(2).replace(/\.?0+$/, '')}%</Chip>
                )}
              </div>
              <div className="w-28 text-right">
                <div className="text-sm">{fmt(r.matches)}</div>
                <div className="text-[10px] text-[var(--muted)]">
                  matches{total > 0 && ` · ${((r.matches / total) * 100).toFixed(1)}%`}
                </div>
              </div>
            </div>
          ))}
          {rules.length === 0 && !error && (
            <div className="px-4 py-10 text-center text-sm text-[var(--muted)]">No rules defined in optic.yaml.</div>
          )}
        </div>
      </div>

      <p className="text-xs text-[var(--muted)]">
        Everything not matched by a rule is captured in full (opt-out model). Redaction and
        restriction apply to recorded telemetry only — live traffic is never modified.
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

function Chip({
  children, tone, icon: Icon,
}: {
  children: React.ReactNode;
  tone: 'warn' | 'accent' | 'good' | 'muted';
  icon?: React.ElementType;
}) {
  const tones = {
    warn: 'border-[var(--warn)]/40 text-[var(--warn)]',
    accent: 'border-[var(--accent)]/40 text-[var(--accent)]',
    good: 'border-[var(--good)]/40 text-[var(--good)]',
    muted: 'border-[var(--border)] text-[var(--muted)]',
  };
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 ${tones[tone]}`}>
      {Icon && <Icon className="h-3 w-3" />}
      {children}
    </span>
  );
}

const fmt = (n: number) => Intl.NumberFormat().format(n);

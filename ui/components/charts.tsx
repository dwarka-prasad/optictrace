'use client';

import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { TimeBucket } from '@/lib/api';

// Series animation is off everywhere in this file. These charts re-poll every
// five seconds, and Recharts replays its enter animation whenever the data
// changes — so a live dashboard spends its time redrawing itself, and a chart
// captured or glanced at mid-animation shows nothing at all.
const tickStyle = { fill: '#7c8cad', fontSize: 11 };
const tooltipStyle = {
  backgroundColor: '#111a2e',
  border: '1px solid #1e2a45',
  borderRadius: 8,
  color: '#e2e8f0',
  fontSize: 12,
};

const fmtTime = (iso: string) =>
  new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

export function TrafficChart({ series }: { series: TimeBucket[] }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={series} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <defs>
          <linearGradient id="reqFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="errFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f87171" stopOpacity={0.5} />
            <stop offset="100%" stopColor="#f87171" stopOpacity={0.05} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#1e2a45" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="time" tickFormatter={fmtTime} tick={tickStyle} axisLine={false} tickLine={false} />
        <YAxis tick={tickStyle} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip
          contentStyle={tooltipStyle}
          labelFormatter={(v) => new Date(v as string).toLocaleString()}
        />
        <Area type="monotone" dataKey="count" name="requests" stroke="#38bdf8" fill="url(#reqFill)" strokeWidth={2} isAnimationActive={false} />
        <Area type="monotone" dataKey="errors" name="5xx errors" stroke="#f87171" fill="url(#errFill)" strokeWidth={2} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/** Average and p95 together.
 *
 *  The average alone was actively misleading: the requests worth investigating
 *  are in the tail, and a handful of 3s responses inside a minute of 5ms ones
 *  move the mean by almost nothing. Shown as a pair so the GAP between them is
 *  the reading — a wide gap means a few requests are having a very different
 *  experience from the typical one. */
export function LatencyChart({ series }: { series: TimeBucket[] }) {
  // A driver that does not compute a per-bucket percentile sends zeros. Drawing
  // a flat line along the axis would read as "no latency", so drop the series.
  const hasTail = series.some((b) => (b.p95_latency_ms ?? 0) > 0);
  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={series} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid stroke="#1e2a45" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="time" tickFormatter={fmtTime} tick={tickStyle} axisLine={false} tickLine={false} />
        <YAxis tick={tickStyle} axisLine={false} tickLine={false} unit="ms" />
        <Tooltip
          contentStyle={tooltipStyle}
          labelFormatter={(v) => new Date(v as string).toLocaleString()}
          formatter={(v, name) => [`${Number(v).toFixed(1)} ms`, name as string]}
        />
        {hasTail && (
          <Line type="monotone" dataKey="p95_latency_ms" name="p95" stroke="#fbbf24" strokeWidth={2} dot={false} connectNulls={false} isAnimationActive={false} />
        )}
        <Line type="monotone" dataKey="avg_latency_ms" name="average" stroke="#34d399" strokeWidth={2} strokeDasharray="4 3" dot={false} connectNulls={false} isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

/** Traffic split by status class.
 *
 *  Stacked, not overlaid: the question this answers is "what proportion of my
 *  traffic is failing", and a proportion needs a common baseline. Colour
 *  carries the severity so the shape is readable without the legend. */
export function StatusMixChart({ series }: { series: TimeBucket[] }) {
  // The stats series carries the total and each failing class; the remainder
  // is everything that succeeded. Deriving it here keeps the API honest — it
  // reports what it measured, not a pre-chewed shape for one chart.
  //
  // 4xx sits between: a rejected request is not a healthy one, but it is also
  // not the service falling over, and stacking them together would turn a
  // caller sending bad input into an incident.
  const data = series.map((b) => ({
    time: b.time,
    ok: Math.max(0, b.count - b.errors - (b.client_errors ?? 0)),
    rejected: b.client_errors ?? 0,
    errors: b.errors,
  }));
  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid stroke="#1e2a45" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="time" tickFormatter={fmtTime} tick={tickStyle} axisLine={false} tickLine={false} />
        <YAxis tick={tickStyle} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} labelFormatter={(v) => new Date(v as string).toLocaleString()} />
        <Area type="monotone" dataKey="ok" stackId="1" name="succeeded" stroke="#34d399" fill="#34d399" fillOpacity={0.25} strokeWidth={1.5} isAnimationActive={false} />
        <Area type="monotone" dataKey="rejected" stackId="1" name="rejected (4xx)" stroke="#fbbf24" fill="#fbbf24" fillOpacity={0.3} strokeWidth={1.5} isAnimationActive={false} />
        <Area type="monotone" dataKey="errors" stackId="1" name="failed (5xx)" stroke="#f87171" fill="#f87171" fillOpacity={0.4} strokeWidth={1.5} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/** A horizontal bar list — for rankings where the label matters more than the
 *  axis (tenants, services, log levels). Reads top-down like a table, which is
 *  how people actually scan a ranking. */
export function BarList({
  items,
  unit = '',
  tone,
}: {
  items: { label: string; value: number; hint?: string }[];
  unit?: string;
  tone?: (label: string) => string;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (items.length === 0) {
    return <p className="py-6 text-center text-xs text-[var(--muted)]">Nothing in this window.</p>;
  }
  return (
    <div className="space-y-2">
      {items.map((i) => (
        <div key={i.label} className="space-y-1">
          <div className="flex items-baseline justify-between gap-2 text-xs">
            <span className="truncate font-mono">{i.label}</span>
            <span className="shrink-0 tabular-nums text-[var(--muted)]">
              {i.hint ?? `${i.value.toLocaleString()}${unit}`}
            </span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-[var(--border)]/60">
            <div
              className="h-full rounded-full"
              style={{
                width: `${(i.value / max) * 100}%`,
                background: tone ? tone(i.label) : 'var(--accent)',
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

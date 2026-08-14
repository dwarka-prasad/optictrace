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
        <Area type="monotone" dataKey="count" name="requests" stroke="#38bdf8" fill="url(#reqFill)" strokeWidth={2} />
        <Area type="monotone" dataKey="errors" name="5xx errors" stroke="#f87171" fill="url(#errFill)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function LatencyChart({ series }: { series: TimeBucket[] }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={series} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <CartesianGrid stroke="#1e2a45" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="time" tickFormatter={fmtTime} tick={tickStyle} axisLine={false} tickLine={false} />
        <YAxis tick={tickStyle} axisLine={false} tickLine={false} unit="ms" />
        <Tooltip
          contentStyle={tooltipStyle}
          labelFormatter={(v) => new Date(v as string).toLocaleString()}
          formatter={(v) => [`${Number(v).toFixed(2)} ms`, 'avg latency']}
        />
        <Line type="monotone" dataKey="avg_latency_ms" stroke="#34d399" strokeWidth={2} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}

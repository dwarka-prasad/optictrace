'use client';

export function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET: 'text-sky-300 border-sky-300/30',
    POST: 'text-emerald-300 border-emerald-300/30',
    PUT: 'text-amber-300 border-amber-300/30',
    PATCH: 'text-amber-300 border-amber-300/30',
    DELETE: 'text-red-300 border-red-300/30',
  };
  return (
    <span
      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${
        colors[method] ?? 'text-[var(--muted)] border-[var(--border)]'
      }`}
    >
      {method}
    </span>
  );
}

export function StatusBadge({ status }: { status: number }) {
  const tone =
    status >= 500
      ? 'text-[var(--bad)] border-[var(--bad)]/40'
      : status >= 400
        ? 'text-[var(--warn)] border-[var(--warn)]/40'
        : 'text-[var(--good)] border-[var(--good)]/40';
  return <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${tone}`}>{status}</span>;
}

/** Marks a long-lived response — SSE, chunked, or an upgraded connection.
 *
 *  Worth its own badge: a stream's duration is how long the client stayed
 *  connected, not how long anything took, so a 600,000ms row is normal rather
 *  than alarming. Percentiles already exclude these; the badge is what stops a
 *  reader drawing the wrong conclusion from the number next to it. */
export function StreamBadge() {
  return (
    <span
      title="Long-lived stream — the duration is a connection lifetime, not a latency, and is excluded from percentiles"
      className="rounded border border-[var(--accent)]/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-[var(--accent)]"
    >
      stream
    </span>
  );
}

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

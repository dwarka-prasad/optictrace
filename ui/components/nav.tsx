'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Activity, Coins, Eye, FileCode2, GitBranch, Route, ScrollText, Server, ShieldCheck, Gauge, Terminal } from 'lucide-react';
import { API_BASE } from '@/lib/api';

const links = [
  { href: '/', label: 'Overview', icon: Activity },
  { href: '/routes', label: 'Routes', icon: Route },
  // Traces before Inspector: "what happened to this request" is the question
  // people arrive with, and the record list is where you go once you know
  // which hop you want.
  { href: '/traces', label: 'Traces', icon: GitBranch },
  { href: '/inspector', label: 'Inspector', icon: ScrollText },
  { href: '/logs', label: 'Logs', icon: Terminal },
  { href: '/usage', label: 'Usage', icon: Coins },
  { href: '/governance', label: 'Governance', icon: ShieldCheck },
  { href: '/config', label: 'Config', icon: FileCode2 },
  { href: '/system', label: 'System', icon: Server },
];

export function Nav() {
  const pathname = usePathname();
  return (
    <aside className="sticky top-0 flex h-screen w-52 shrink-0 flex-col border-r border-[var(--border)] bg-[var(--panel)] px-3 py-5">
      <div className="mb-8 flex items-center gap-2 px-2">
        <Eye className="h-6 w-6 text-[var(--accent)]" />
        <span className="text-lg font-semibold tracking-wide">OpticTrace</span>
      </div>
      <nav className="flex flex-col gap-1">
        {links.map(({ href, label, icon: Icon }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${
                active
                  ? 'bg-[var(--accent)]/10 text-[var(--accent)]'
                  : 'text-[var(--muted)] hover:bg-white/5 hover:text-[var(--text)]'
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
            </Link>
          );
        })}
      </nav>
      <div className="mt-auto px-3 text-xs text-[var(--muted)]">
        <a
          href={`${API_BASE}/metrics`}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1.5 hover:text-[var(--accent)]"
        >
          <Gauge className="h-3.5 w-3.5" /> Prometheus /metrics
        </a>
      </div>
    </aside>
  );
}

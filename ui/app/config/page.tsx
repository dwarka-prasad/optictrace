'use client';

import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, FileCode2, RotateCw, XCircle } from 'lucide-react';
import { fetchConfig, reloadConfig, validateConfig } from '@/lib/api';

type Validation = { valid: boolean; error?: string; service?: string; rules?: number } | null;

export default function ConfigPage() {
  const [yaml, setYaml] = useState('');
  const [fileName, setFileName] = useState('optic.yaml');
  const [validation, setValidation] = useState<Validation>(null);
  const [reloadMsg, setReloadMsg] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const debounce = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    fetchConfig()
      .then((c) => {
        setYaml(c.raw);
        setFileName(c.path);
        setValidation({ valid: c.valid, error: c.error, service: c.service, rules: c.rules });
      })
      .catch((e) => setLoadError(e instanceof Error ? e.message : String(e)));
  }, []);

  // Live validation against the agent as the user types.
  const onEdit = (next: string) => {
    setYaml(next);
    clearTimeout(debounce.current);
    debounce.current = setTimeout(async () => {
      try {
        setValidation(await validateConfig(next));
      } catch {
        setValidation({ valid: false, error: 'agent unreachable' });
      }
    }, 400);
  };

  const onReload = async () => {
    setReloadMsg(null);
    try {
      const res = await reloadConfig();
      setReloadMsg(res.reloaded ? 'Agent reloaded optic.yaml from disk.' : (res.error ?? 'reload failed'));
    } catch (e) {
      setReloadMsg(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <FileCode2 className="h-5 w-5 text-[var(--accent)]" /> {fileName}
        </h1>
        <button
          onClick={onReload}
          className="flex items-center gap-1.5 rounded-lg border border-[var(--accent)]/40 px-3 py-1.5 text-xs text-[var(--accent)] hover:bg-[var(--accent)]/10"
          title="Re-read optic.yaml from disk and hot-swap the rule engine"
        >
          <RotateCw className="h-3.5 w-3.5" /> Hot reload from disk
        </button>
      </div>

      <p className="text-sm text-[var(--muted)]">
        Edits here validate live against the running agent, but are <b>not written back</b> — treat
        optic.yaml as code: change it in your repo, ship it, then hot-reload. This editor is a linting
        scratchpad.
      </p>

      {loadError && <div className="panel border-[var(--bad)]/40 p-4 text-sm text-[var(--bad)]">{loadError}</div>}
      {reloadMsg && <div className="panel border-[var(--accent)]/30 p-3 text-sm">{reloadMsg}</div>}

      <div className="panel overflow-hidden">
        <div
          className={`flex items-center gap-2 border-b px-4 py-2 text-xs ${
            validation?.valid
              ? 'border-[var(--good)]/30 text-[var(--good)]'
              : validation
                ? 'border-[var(--bad)]/30 text-[var(--bad)]'
                : 'border-[var(--border)] text-[var(--muted)]'
          }`}
        >
          {validation?.valid ? (
            <>
              <CheckCircle2 className="h-3.5 w-3.5" />
              Valid — service “{validation.service}”, {validation.rules} rule(s)
            </>
          ) : validation ? (
            <>
              <XCircle className="h-3.5 w-3.5" /> {validation.error}
            </>
          ) : (
            'Validating…'
          )}
        </div>
        <textarea
          value={yaml}
          onChange={(e) => onEdit(e.target.value)}
          spellCheck={false}
          className="h-[65vh] w-full resize-none bg-black/20 p-4 font-mono text-xs leading-relaxed outline-none"
        />
      </div>
    </div>
  );
}

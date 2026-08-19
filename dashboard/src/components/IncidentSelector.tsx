import { useEffect, useMemo, useState, type FormEvent } from 'react';

interface Props {
  selectedId: number | null;
  onSelect: (id: number) => void;
}

function parseIncidentId(value: string): number | null {
  const normalized = value.trim();

  if (!/^(0|[1-9]\d*)$/.test(normalized)) return null;

  const id = Number(normalized);
  return Number.isSafeInteger(id) && id >= 0 ? id : null;
}

export function IncidentSelector({ selectedId, onSelect }: Props) {
  const [draft, setDraft] = useState(selectedId?.toString() ?? '');

  useEffect(() => {
    setDraft(selectedId?.toString() ?? '');
  }, [selectedId]);

  const parsedId = useMemo(() => parseIncidentId(draft), [draft]);
  const invalid = draft.trim().length > 0 && parsedId === null;

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (parsedId !== null) onSelect(parsedId);
  };

  return (
    <form onSubmit={submit} className="flex flex-wrap items-start gap-2" aria-label="Analyze an incident">
      <div>
        <label htmlFor="incident-id" className="sr-only">Incident ID</label>
        <input
          id="incident-id"
          type="text"
          inputMode="numeric"
          autoComplete="off"
          value={draft}
          placeholder="Incident ID"
          onChange={(event) => setDraft(event.target.value)}
          aria-invalid={invalid}
          aria-describedby={invalid ? 'incident-id-error' : undefined}
          className="w-36 rounded-md border border-hydra-border bg-hydra-surface px-2 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-hydra-accent focus:ring-2 focus:ring-hydra-accent/20"
        />
        {invalid && (
          <p id="incident-id-error" role="alert" className="mt-1 max-w-52 text-xs text-red-400">
            Enter a nonnegative safe integer.
          </p>
        )}
      </div>
      <button
        type="submit"
        disabled={parsedId === null}
        className="rounded-md border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-sm font-medium text-cyan-200 transition-colors hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-40"
      >
        Analyze
      </button>
    </form>
  );
}

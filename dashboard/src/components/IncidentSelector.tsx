import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { fetchIncidents } from '../lib/api-client';
import type { IncidentListItem } from '../lib/api-types';

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

function describeInterval(incident: IncidentListItem): string {
  const start = new Date(incident.intervalStart).toISOString().slice(0, 16).replace('T', ' ');
  return incident.intervalEnd === null ? `${start} → open` : `${start} → closed`;
}

export function IncidentSelector({ selectedId, onSelect }: Props) {
  const [draft, setDraft] = useState(selectedId?.toString() ?? '');
  const [incidents, setIncidents] = useState<readonly IncidentListItem[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [manual, setManual] = useState(false);

  useEffect(() => {
    setDraft(selectedId?.toString() ?? '');
  }, [selectedId]);

  useEffect(() => {
    const controller = new AbortController();

    fetchIncidents({ signal: controller.signal })
      .then((response) => {
        setIncidents(response.incidents);
        setListError(null);
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
        // Falling back to manual entry keeps the view usable when the index is down.
        setIncidents([]);
        setListError(cause instanceof Error ? cause.message : 'Incident index unavailable');
      });

    return () => controller.abort();
  }, []);

  const parsedId = useMemo(() => parseIncidentId(draft), [draft]);
  const invalid = draft.trim().length > 0 && parsedId === null;
  const showList = !manual && incidents !== null && incidents.length > 0;

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (parsedId !== null) onSelect(parsedId);
  };

  if (showList) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="incident-select" className="sr-only">Incident</label>
        <select
          id="incident-select"
          value={selectedId ?? ''}
          onChange={(event) => {
            const id = parseIncidentId(event.target.value);
            if (id !== null) onSelect(id);
          }}
          className="max-w-80 rounded-md border border-hydra-border bg-hydra-surface px-2 py-1.5 text-sm text-gray-200 outline-none transition-colors focus:border-hydra-accent focus:ring-2 focus:ring-hydra-accent/20"
        >
          <option value="" disabled>Select an incident…</option>
          {incidents.map((incident) => (
            <option key={incident.incidentId} value={incident.incidentId}>
              #{incident.incidentId} · {incident.title}
              {incident.synthetic ? ' [demo]' : ''} · {incident.affectedVersionCount} affected · {describeInterval(incident)}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setManual(true)}
          className="rounded-md border border-hydra-border px-2 py-1.5 text-xs text-hydra-muted transition-colors hover:text-gray-200"
        >
          Enter ID
        </button>
      </div>
    );
  }

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
        {listError !== null && !invalid && (
          <p className="mt-1 max-w-64 text-xs text-yellow-500/80">
            Incident list unavailable; enter an ID directly.
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
      {incidents !== null && incidents.length > 0 && (
        <button
          type="button"
          onClick={() => setManual(false)}
          className="rounded-md border border-hydra-border px-2 py-1.5 text-xs text-hydra-muted transition-colors hover:text-gray-200"
        >
          Browse list
        </button>
      )}
    </form>
  );
}

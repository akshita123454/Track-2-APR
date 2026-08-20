import { useState } from 'react';
import type { TyposquattingFindingStatus } from '../lib/api-types';
import { useTyposquatting } from '../hooks/useTyposquatting';

const STATUS_STYLE: Record<TyposquattingFindingStatus, string> = {
  candidate: 'border-slate-500/40 bg-slate-500/10 text-slate-300',
  suspicious: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-300',
  'high-confidence': 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  confirmed: 'border-red-500/40 bg-red-500/10 text-red-300',
  dismissed: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
};

export interface TyposquattingViewProps {
  readonly findingId: number | null;
  readonly onSelectFinding: (findingId: number) => void;
}

export function TyposquattingView({ findingId, onSelectFinding }: TyposquattingViewProps) {
  const { list, detail, loading, detailLoading, actionLoading, error, refetch, review } = useTyposquatting(findingId);
  const [reason, setReason] = useState('Reviewed against lockfile and graph evidence.');
  const terminal = detail?.finding.status === 'confirmed' || detail?.finding.status === 'dismissed';

  return (
    <main className="min-h-0 flex-1 overflow-y-auto px-4 py-5 sm:px-6">
      <div className="mx-auto grid max-w-7xl gap-5 lg:grid-cols-[22rem_minmax(0,1fr)]">
        <section className="hydra-card overflow-hidden">
          <div className="border-b border-hydra-border p-4">
            <h1 className="text-lg font-semibold">Typosquatting findings</h1>
            <p className="mt-1 text-xs text-hydra-muted">Backend classifications from verified lockfile observations. Similarity alone is not maliciousness.</p>
          </div>
          {loading && <p className="p-4 text-sm text-hydra-muted">Loading findings…</p>}
          {!loading && list?.findings.length === 0 && <p className="p-4 text-sm text-hydra-muted">No findings have been persisted.</p>}
          <div className="max-h-[70vh] overflow-y-auto">
            {list?.findings.map((finding) => (
              <button
                key={finding.findingId}
                type="button"
                onClick={() => onSelectFinding(finding.findingId)}
                className={`block w-full border-b border-hydra-border p-4 text-left hover:bg-white/[0.03] ${findingId === finding.findingId ? 'bg-cyan-500/[0.06]' : ''}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-sm">{finding.candidateName}</span>
                  <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${STATUS_STYLE[finding.status]}`}>{finding.status}</span>
                </div>
                <p className="mt-1 truncate text-xs text-hydra-muted">resembles {finding.targetName}</p>
                <p className="mt-2 text-xs"><span className="font-semibold text-hydra-accent">{finding.score}/100</span> heuristic ranking</p>
                {finding.synthetic && <span className="mt-2 inline-block rounded border border-purple-500/40 bg-purple-500/10 px-2 py-0.5 text-[10px] font-semibold text-purple-300">SYNTHETIC DATA</span>}
              </button>
            ))}
          </div>
          {list?.truncated && <p className="p-3 text-xs text-yellow-300">Result page is truncated; use the API cursor for the next page.</p>}
        </section>

        <section className="hydra-card min-h-[32rem] p-5">
          {error && (
            <div className="mb-4 rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">
              {error} <button type="button" className="ml-2 underline" onClick={() => void refetch()}>Retry</button>
            </div>
          )}
          {findingId === null && <div className="grid h-full place-items-center text-sm text-hydra-muted">Select a finding to inspect its evidence and exposure.</div>}
          {findingId !== null && detailLoading && <p className="text-sm text-hydra-muted">Loading finding evidence…</p>}
          {detail && !detailLoading && (
            <div className="space-y-6">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="font-mono text-xl font-semibold">{detail.finding.candidateName}</h2>
                  <span className="text-hydra-muted">→</span>
                  <span className="font-mono text-lg">{detail.finding.targetName}</span>
                  <span className={`rounded border px-2 py-0.5 text-xs font-semibold uppercase ${STATUS_STYLE[detail.finding.status]}`}>{detail.finding.status}</span>
                </div>
                <p className="mt-2 text-sm text-hydra-muted">{detail.finding.summary}</p>
                <div className="mt-3 rounded border border-cyan-500/30 bg-cyan-500/[0.06] p-3 text-sm">
                  <strong>{detail.finding.score}/100 heuristic ranking.</strong> This is not a probability and does not independently assert maliciousness.
                </div>
                {detail.finding.synthetic && <div className="mt-3 rounded border border-purple-500/40 bg-purple-500/10 p-3 text-sm font-semibold text-purple-200">Synthetic demonstration evidence — do not treat as a real compromise.</div>}
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <h3 className="text-sm font-semibold uppercase tracking-wide text-hydra-muted">Why it matched</h3>
                  <div className="mt-2 flex flex-wrap gap-2">{detail.finding.transformations.map((value) => <span key={value} className="rounded bg-slate-700/60 px-2 py-1 text-xs">{value}</span>)}</div>
                  <ul className="mt-3 space-y-1 text-xs text-slate-300">{detail.finding.reasonCodes.map((code) => <li key={code}>• {code}</li>)}</ul>
                </div>
                <div>
                  <h3 className="text-sm font-semibold uppercase tracking-wide text-hydra-muted">Exact lockfile versions</h3>
                  <div className="mt-2 flex flex-wrap gap-2">{detail.exactVersions.length === 0 ? <span className="text-sm text-hydra-muted">No exact matching version evidence.</span> : detail.exactVersions.map((version) => <span key={version.id} className="rounded bg-slate-700/60 px-2 py-1 font-mono text-xs">{detail.finding.candidateName}@{version.version}</span>)}</div>
                  {detail.versionLookup.truncated && <p className="mt-2 text-xs text-yellow-300">Version lookup was truncated.</p>}
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold uppercase tracking-wide text-hydra-muted">Evidence ledger</h3>
                <div className="mt-2 grid gap-2 sm:grid-cols-2">{detail.evidence.map((entry) => (
                  <div key={entry.id} className="rounded border border-hydra-border bg-black/10 p-3 text-xs">
                    <div className="flex justify-between gap-2"><span className="font-medium">{entry.sourceType}</span><span>{Math.round(entry.confidence * 100)}% provenance confidence</span></div>
                    <p className="mt-1 text-hydra-muted">Evidence #{entry.id}</p>
                    {entry.synthetic && <span className="mt-1 inline-block font-semibold text-purple-300">SYNTHETIC</span>}
                  </div>
                ))}</div>
              </div>

              <div>
                <h3 className="text-sm font-semibold uppercase tracking-wide text-hydra-muted">Service exposure</h3>
                {detail.exposure.services.length === 0 ? <p className="mt-2 text-sm text-hydra-muted">No evidence-matched service path was returned. Unknown is not safe.</p> : (
                  <div className="mt-2 space-y-2">{detail.exposure.services.map((service) => (
                    <div key={service.serviceId} className="rounded border border-hydra-border p-3 text-sm">
                      <div className="flex justify-between gap-3"><strong>{service.serviceName}</strong><span className="uppercase text-hydra-muted">{service.serviceCriticality}</span></div>
                      <p className="mt-1 text-xs text-hydra-muted">Exact dependency path: {service.packageVersionIds.join(' → ')}</p>
                    </div>
                  ))}</div>
                )}
                {detail.exposure.truncated && <p className="mt-2 text-xs text-yellow-300">Exposure traversal reached a configured safety bound.</p>}
              </div>

              {detail.incidentIds.length > 0 && <p className="rounded border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">Confirmed incident: {detail.incidentIds.join(', ')}</p>}

              {!terminal && (
                <div className="border-t border-hydra-border pt-5">
                  <h3 className="text-sm font-semibold uppercase tracking-wide text-hydra-muted">Analyst decision</h3>
                  <div className="mt-3 grid gap-3">
                    <p className="text-xs text-hydra-muted">Reviewer identity is derived by the API from the authenticated analyst bearer token.</p>
                    <label className="text-xs text-hydra-muted">Reason<textarea className="mt-1 min-h-20 w-full rounded border border-hydra-border bg-black/20 px-3 py-2 text-sm text-white" value={reason} onChange={(event) => setReason(event.target.value)} /></label>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button type="button" disabled={actionLoading || !reason.trim()} onClick={() => void review('dismiss', { reason: reason.trim() })} className="rounded border border-emerald-500/40 px-3 py-2 text-sm text-emerald-300 disabled:opacity-50">Dismiss finding</button>
                    <button type="button" disabled={actionLoading || detail.finding.synthetic || detail.exactVersions.length === 0 || !reason.trim()} onClick={() => void review('promote', { reason: reason.trim() })} className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200 disabled:opacity-50">Confirm and create incident</button>
                  </div>
                  <p className="mt-2 text-xs text-hydra-muted">Confirmation is an explicit analyst action and requires trusted non-synthetic lockfile evidence plus an exact resolved version.</p>
                </div>
              )}
              {terminal && detail.finding.decisionReason && <div className="border-t border-hydra-border pt-4 text-sm"><strong>Decision:</strong> {detail.finding.decisionReason}</div>}
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

import type { LiveBlastRadiusResponse } from '../lib/api-types';

export function AnalysisLimitBanner({ data }: { data: LiveBlastRadiusResponse }) {
  if (!data.truncated && !data.affectedVersionLookup.truncated && data.evidenceFunnel.completeForIncident && data.evidenceFunnel.evidenceLookup.complete) return null;

  return (
    <div className="border-b border-hydra-warning/30 bg-hydra-warning/10 p-4" role="alert">
      <div className="flex items-start gap-3 text-hydra-warning">
        <svg className="mt-0.5 h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
        <div>
          <h3 className="text-sm font-bold tracking-wide">PARTIAL ANALYSIS</h3>
          <p className="mt-1 text-sm text-yellow-200/80">One or more read, traversal, or evidence boundaries were reached. Additional affected versions, services, paths, or evidence may exist.</p>
          <ul className="mt-2 list-inside list-disc space-y-1 text-xs opacity-75">
            {data.warnings.map((warning, index) => <li key={`${warning.code}-${index}`}>{warning.message}</li>)}
            {data.truncated && data.warnings.length === 0 && <li>A traversal or response limit was reached.</li>}
            {data.affectedVersionLookup.truncated && <li>Affected-version lookup limit reached.</li>}
            {!data.evidenceFunnel.completeForIncident && <li>The evidence funnel is incomplete for the full incident.</li>}
            {!data.evidenceFunnel.evidenceLookup.complete && <li>The returned evidence lookup is incomplete.</li>}
          </ul>
        </div>
      </div>
    </div>
  );
}

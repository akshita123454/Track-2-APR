export function GraphLegend() {
  return (
    <div className="max-w-xs rounded-lg border border-hydra-border bg-hydra-surface p-3 text-xs shadow-lg">
      <div className="mb-2 font-semibold tracking-wide text-gray-300">LEGEND</div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2">
        <div className="flex items-center gap-2"><svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><polygon points="7,1 13,4 13,10 7,13 1,10 1,4" fill="#7f1d1d" stroke="#ef4444" strokeWidth="1.5" /></svg><span>Affected version</span></div>
        <div className="flex items-center gap-2"><div className="h-3.5 w-3.5 rounded-full border border-cyan-500 bg-cyan-900/60" /><span>Service</span></div>
        <div className="flex items-center gap-2"><div className="h-3.5 w-3.5 rounded border border-gray-500 bg-gray-800" /><span>Package</span></div>
        <div className="flex items-center gap-2"><div className="h-3.5 w-3.5 rounded-full border-2 border-red-500 bg-cyan-900/60" /><span>Critical service</span></div>

        <div className="col-span-2 mb-1 mt-2 border-t border-hydra-border pt-2 font-medium text-gray-400">Entity evidence state</div>
        <div className="flex items-center gap-2"><div className="h-0.5 w-4 bg-gray-500" /><span>No resolved evidence</span></div>
        <div className="flex items-center gap-2"><div className="h-0.5 w-4 bg-amber-500" /><span>Evidence resolved</span></div>
        <div className="flex items-center gap-2"><div className="h-0.5 w-4 bg-emerald-500" /><span>High-confidence</span></div>
        <div className="flex items-center gap-2"><div className="h-0.5 w-4 bg-purple-500" /><span>DEMO provenance</span></div>
        <p className="col-span-2 mt-1 text-[11px] leading-4 text-gray-500">Path verdicts are evaluated separately across every canonical edge in the proof ledger.</p>
      </div>
    </div>
  );
}

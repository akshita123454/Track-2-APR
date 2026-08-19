export function EmptyState() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center p-8 text-hydra-muted">
      <svg className="mb-6 h-24 w-24 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0zM10 7v3m0 0v3m0-3h3m-3 0H7" />
      </svg>
      <h2 className="text-center text-xl font-medium text-gray-400">Enter an incident ID to inspect its candidate blast radius</h2>
      <p className="mt-2 max-w-lg text-center text-sm leading-6">
        HydraGuard analyzes recorded dependency relationships and evidence to identify candidate services affected by an incident—without claiming deployment, reachability, execution, or compromise.
      </p>
    </div>
  );
}

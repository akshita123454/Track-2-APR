export function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-1 items-center justify-center p-8" role="alert">
      <div className="max-w-lg rounded-lg border border-red-500/30 bg-red-900/10 p-6 text-center">
        <svg className="mx-auto mb-4 h-12 w-12 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <h3 className="mb-2 text-lg font-semibold text-red-400">Analysis unavailable</h3>
        <p className="mb-6 text-gray-300">{message}</p>
        <button type="button" onClick={onRetry} className="rounded border border-hydra-border bg-hydra-surface px-4 py-2 text-sm transition-colors hover:bg-hydra-border focus:ring-2 focus:ring-hydra-accent/30">Try again</button>
      </div>
    </div>
  );
}

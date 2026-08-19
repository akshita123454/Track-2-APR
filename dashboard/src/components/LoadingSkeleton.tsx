export function LoadingSkeleton() {
  return (
    <div className="p-8 motion-safe:animate-pulse" role="status" aria-live="polite" aria-label="Loading incident analysis">
      <span className="sr-only">Loading incident analysis…</span>
      <div className="mb-8 h-12 w-1/3 rounded-lg bg-hydra-border" />
      <div className="mb-12 space-y-4">
        <div className="h-4 w-1/4 rounded bg-hydra-border" />
        <div className="h-8 w-full rounded-lg bg-hydra-border" />
        <div className="h-8 w-3/4 rounded-lg bg-hydra-border" />
        <div className="h-8 w-1/2 rounded-lg bg-hydra-border" />
      </div>
      <div className="mt-20 flex flex-wrap justify-center gap-12">
        <div className="h-32 w-32 rounded-full bg-hydra-border" />
        <div className="h-32 w-32 rounded-full bg-hydra-border" />
        <div className="h-32 w-32 rounded-full bg-hydra-border" />
      </div>
    </div>
  );
}

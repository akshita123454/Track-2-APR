interface NoServiceStateProps {
  affectedVersionCount: number;
}

export function NoServiceState({ affectedVersionCount }: NoServiceStateProps) {
  return (
    <section className="flex flex-1 items-center justify-center p-8" aria-labelledby="no-services-heading">
      <div className="hydra-card max-w-2xl p-8 text-center">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-300" aria-hidden="true">○</div>
        <h2 id="no-services-heading" className="text-lg font-semibold text-gray-200">No service candidates returned</h2>
        <p className="mt-2 text-sm leading-6 text-gray-400">
          HydraGuard resolved {affectedVersionCount} affected package {affectedVersionCount === 1 ? 'version' : 'versions'}, but found no dependent services within the applied analysis limits.
        </p>
        <p className="mt-3 text-xs text-amber-300/80">
          This does not prove that no affected services exist outside those limits or in unobserved dependency data.
        </p>
      </div>
    </section>
  );
}

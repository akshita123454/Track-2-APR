import { useEffect, useState } from 'react';
import { IncidentSelector } from './components/IncidentSelector';
import { IncidentHeader } from './components/IncidentHeader';
import { EvidenceFunnel } from './components/EvidenceFunnel';
import { HydraTelemetry } from './components/HydraTelemetry';
import { GraphCanvas } from './components/GraphCanvas';
import { GraphLegend } from './components/GraphLegend';
import { WhyAffectedPanel } from './components/WhyAffectedPanel';
import { AnalysisLimitBanner } from './components/AnalysisLimitBanner';
import { LoadingSkeleton } from './components/LoadingSkeleton';
import { ErrorState } from './components/ErrorState';
import { EmptyState } from './components/EmptyState';
import { NoServiceState } from './components/NoServiceState';
import { useBlastRadius } from './hooks/useBlastRadius';

function getInitialIncidentId(): number | null {
  const raw = new URLSearchParams(window.location.search).get('incidentId');
  if (raw === null || !/^(0|[1-9]\d*)$/.test(raw)) return null;

  const id = Number(raw);
  return Number.isSafeInteger(id) && id >= 0 ? id : null;
}

export default function App() {
  const [incidentId, setIncidentId] = useState<number | null>(getInitialIncidentId);
  const [selectedServiceId, setSelectedServiceId] = useState<number | null>(null);
  const [selectedPathKey, setSelectedPathKey] = useState<string | null>(null);
  const { data, loading, error, refetch } = useBlastRadius(incidentId);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (incidentId === null) url.searchParams.delete('incidentId');
    else url.searchParams.set('incidentId', incidentId.toString());
    window.history.replaceState(null, '', url.toString());
  }, [incidentId]);

  const selectedService = data?.services.find(({ service }) => service.id === selectedServiceId);
  const selectedPath = selectedService?.paths.find((path) => path.pathKey === selectedPathKey)
    ?? selectedService?.paths[0]
    ?? null;

  const selectIncident = (id: number) => {
    setIncidentId(id);
    setSelectedServiceId(null);
    setSelectedPathKey(null);
  };

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex flex-col gap-3 border-b border-hydra-border px-4 py-3 sm:px-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-start gap-3">
          <span className="pt-1 text-xl font-bold tracking-tight"><span className="text-hydra-accent">Hydra</span>Guard</span>
          <IncidentSelector selectedId={incidentId} onSelect={selectIncident} />
        </div>
        {!loading && !error && data && <HydraTelemetry telemetry={data.hydraRead} />}
      </header>

      <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {loading && <LoadingSkeleton />}
        {!loading && error && <ErrorState message={error} onRetry={refetch} />}
        {!loading && !error && !data && <EmptyState />}

        {!loading && !error && data && (
          <>
            <AnalysisLimitBanner data={data} />

            <div className="border-b border-hydra-border px-4 py-4 sm:px-6">
              <IncidentHeader incident={data.incident} affectedVersions={data.affectedVersions} />
            </div>

            <div className="border-b border-hydra-border px-4 py-4 sm:px-6">
              <EvidenceFunnel funnel={data.evidenceFunnel} />
            </div>

            {data.services.length === 0 ? (
              <NoServiceState affectedVersionCount={data.affectedVersions.length} />
            ) : (
              <div className="flex min-h-0 flex-1 flex-col overflow-hidden xl:flex-row">
                <div className="relative min-h-[32rem] min-w-0 flex-1">
                  <GraphCanvas
                    data={data}
                    selectedServiceId={selectedServiceId}
                    selectedPathKey={selectedPathKey}
                    onSelectService={setSelectedServiceId}
                    onSelectPath={setSelectedPathKey}
                  />
                  <div className="absolute bottom-4 left-4"><GraphLegend /></div>
                </div>

                {selectedService && (
                  <div className="max-h-[46rem] w-full overflow-y-auto border-t border-hydra-border xl:max-h-none xl:w-96 xl:flex-none xl:border-l xl:border-t-0">
                    <WhyAffectedPanel
                      service={selectedService}
                      selectedPath={selectedPath}
                      evidenceCatalog={data.evidenceCatalog}
                      highConfidenceThreshold={data.evidenceFunnel.highConfidenceThreshold}
                      onSelectPath={setSelectedPathKey}
                    />
                  </div>
                )}
              </div>
            )}

            <footer className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-hydra-border px-4 py-2 text-xs text-hydra-muted sm:px-6">
              <span>Read epoch: {data.hydraRead.readEpoch}</span>
              <span aria-hidden="true">·</span>
              <span>{data.hydraRead.engine} · {data.hydraRead.consistencyModel}</span>
              {data.incident.synthetic && <span className="rounded border border-purple-500/30 bg-purple-500/10 px-1.5 font-medium text-purple-400">DEMO DATA</span>}
              {data.evidenceFunnel.limitations.length > 0 && <span className="text-yellow-500/80">{data.evidenceFunnel.limitations[0]}</span>}
            </footer>
          </>
        )}
      </main>
    </div>
  );
}

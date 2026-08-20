import type {
  ServiceCandidate,
  BlastRadiusPath,
  EvidenceCatalogEntry,
  ServiceImpactExplanation,
} from '../lib/api-types';
import { EvidenceLedger } from './EvidenceLedger';

interface WhyAffectedPanelProps {
  service: ServiceCandidate;
  impact: ServiceImpactExplanation;
  selectedPath: BlastRadiusPath | null;
  evidenceCatalog: readonly EvidenceCatalogEntry[];
  onSelectPath: (pathKey: string) => void;
}

const confidenceBadgeTone: Record<ServiceImpactExplanation['confidence']['level'], string> = {
  confirmed: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  strong: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  probable: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  possible: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  contextual: 'border-blue-500/30 bg-blue-500/10 text-blue-300',
  unknown: 'border-gray-600 bg-gray-700/50 text-gray-300',
};

export function WhyAffectedPanel({
  service,
  impact,
  selectedPath,
  evidenceCatalog,
  onSelectPath,
}: WhyAffectedPanelProps) {
  const selectedPathAssessment = selectedPath === null
    ? null
    : impact.paths.find((assessment) => assessment.pathKey === selectedPath.pathKey) ?? null;

  return (
    <aside className="flex h-full flex-col bg-hydra-surface" aria-label={`Evidence for ${service.service.name}`}>
      <div className="border-b border-hydra-border bg-hydra-bg/50 p-4">
        <h2 className="mb-1 text-xs font-semibold tracking-wider text-gray-500">WHY IS THIS SERVICE {impact.conclusion.toUpperCase()}?</h2>
        <div className="break-words text-lg font-semibold text-gray-100">{service.service.name}</div>
        <p className="mt-2 text-xs leading-relaxed text-gray-400">{impact.summary}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-xs font-medium text-cyan-300">
            Stage: {impact.stage.replace(/-/g, ' ')}
          </span>
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${confidenceBadgeTone[impact.confidence.level]}`}>
            Confidence: {impact.confidence.level}
          </span>
          <span className={`rounded border px-2 py-0.5 text-xs font-medium ${
            service.service.criticality === 'critical' ? 'border-red-500/20 bg-red-500/10 text-red-400' :
            service.service.criticality === 'high' ? 'border-orange-500/20 bg-orange-500/10 text-orange-400' :
            service.service.criticality === 'medium' ? 'border-yellow-500/20 bg-yellow-500/10 text-yellow-400' :
            'border-blue-500/20 bg-blue-500/10 text-blue-400'
          }`}>
            {service.service.criticality.toUpperCase()}
          </span>
          <span className="rounded border border-gray-600 bg-gray-700/50 px-2 py-0.5 text-xs font-medium text-gray-300">Depth: {service.minimumDepth}</span>
          {service.service.internetExposed && (
            <span className="rounded border border-red-600/30 bg-red-700/10 px-2 py-0.5 text-xs font-medium text-red-300">Internet-exposed metadata</span>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        <h3 className="mb-3 text-sm font-semibold tracking-wider text-gray-400">CANDIDATE DEPENDENCY PATHS ({service.paths.length})</h3>

        <div className="mb-6 space-y-2">
          {service.paths.map((path) => {
            const directDependency = path.nodes[path.nodes.length - 2];
            const viaLabel = directDependency?.kind === 'PackageVersion'
              ? `via ${directDependency.packageName}@${directDependency.version}`
              : directDependency?.kind === 'Service'
                ? `via ${directDependency.name}`
                : 'Direct dependency unavailable';

            return (
              <button
                type="button"
                key={path.pathKey}
                onClick={() => onSelectPath(path.pathKey)}
                aria-pressed={selectedPath?.pathKey === path.pathKey}
                className={`w-full rounded border p-2.5 text-left text-sm transition-colors ${
                  selectedPath?.pathKey === path.pathKey
                    ? 'border-hydra-accent bg-hydra-accent/10 text-cyan-100'
                    : 'border-hydra-border bg-transparent text-gray-400 hover:border-gray-500'
                }`}
              >
                <div className="truncate font-medium" title={viaLabel}>{viaLabel}</div>
                <div className="mt-0.5 text-xs opacity-70">{path.depth} hops · {path.canonicalEdges.length} canonical edges</div>
              </button>
            );
          })}
        </div>

        {selectedPath && selectedPathAssessment && (
          <div>
            <h3 className="mb-3 text-sm font-semibold tracking-wider text-gray-400">CANONICAL DEPENDENCY PROOF</h3>
            <div className="relative space-y-4 border-l-2 border-hydra-border pl-4">
              {[...selectedPath.nodes].reverse().map((node, reversedIndex) => {
                const originalIndex = selectedPath.nodes.length - 1 - reversedIndex;
                const isAffected = originalIndex === 0 && node.kind === 'PackageVersion' && selectedPath.affectedVersionId === node.id;
                const edgeToNext = originalIndex > 0 ? selectedPath.canonicalEdges[originalIndex - 1] : null;

                return (
                  <div key={node.id} className="relative">
                    <div className={`absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full border-2 ${
                      isAffected ? 'border-red-400 bg-red-500' :
                      node.kind === 'Service' ? 'border-cyan-400 bg-cyan-500' :
                      'border-gray-400 bg-gray-500'
                    }`} />
                    <div className="break-words text-sm font-medium text-gray-200">{node.kind === 'Service' ? node.name : node.packageName}</div>
                    {node.kind === 'PackageVersion' && <div className="mt-0.5 text-xs text-gray-500">v{node.version}</div>}
                    {edgeToNext && <div className="ml-1 mt-2 text-xs italic text-hydra-muted">↓ DEPENDS_ON · {edgeToNext.dependencyType}</div>}
                  </div>
                );
              })}
            </div>

            <EvidenceLedger
              path={selectedPath}
              assessment={selectedPathAssessment}
              evidenceCatalog={evidenceCatalog}
            />
          </div>
        )}
      </div>
    </aside>
  );
}

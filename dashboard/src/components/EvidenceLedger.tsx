import type {
  BlastRadiusPath,
  EvidenceCatalogEntry,
  NodeId,
  PathImpactAssessment,
} from '../lib/api-types';

interface EvidenceLedgerProps {
  path: BlastRadiusPath;
  assessment: PathImpactAssessment;
  evidenceCatalog: readonly EvidenceCatalogEntry[];
}

const confidenceTone: Record<PathImpactAssessment['confidence']['level'], string> = {
  confirmed: 'text-emerald-300',
  strong: 'text-emerald-400',
  probable: 'text-amber-300',
  possible: 'text-amber-400',
  contextual: 'text-blue-300',
  unknown: 'text-gray-300',
};

export function EvidenceLedger({
  path,
  assessment,
  evidenceCatalog,
}: EvidenceLedgerProps) {
  const evidenceLookup = new Map<number, EvidenceCatalogEntry>();
  for (const evidence of evidenceCatalog) evidenceLookup.set(evidence.id, evidence);

  const resolvedEdges = path.canonicalEdges.map((edge) => ({
    edge,
    resolved: edge.evidenceIds
      .map((id) => evidenceLookup.get(id))
      .filter((evidence): evidence is EvidenceCatalogEntry => evidence !== undefined),
  }));

  const incidentEvidence = evidenceCatalog
    .filter((evidence) => evidence.incidentLinked)
    .sort((left, right) => right.confidence - left.confidence);

  const getNodeName = (id: NodeId) => {
    const node = path.nodes.find((candidate) => candidate.id === id);
    if (!node) return `Node ${id}`;
    return node.kind === 'Service' ? node.name : `${node.packageName}@${node.version}`;
  };

  return (
    <section className="mt-8 border-t border-hydra-border pt-6" aria-labelledby="proof-ledger-heading">
      <h3 id="proof-ledger-heading" className="mb-4 text-xs font-semibold tracking-wider text-gray-500">PROOF LEDGER</h3>

      <div className="mb-6 rounded-lg border border-hydra-border bg-hydra-bg/50 p-3">
        <div className="mb-1 text-xs font-medium text-gray-400">BACKEND PATH DECISION</div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-xs font-medium text-cyan-300">
            {assessment.stage.replace(/-/g, ' ').toUpperCase()}
          </span>
          <span className={`font-medium ${confidenceTone[assessment.confidence.level]}`}>
            {assessment.confidence.level.replace(/-/g, ' ')} confidence
          </span>
          {assessment.confidence.synthetic && (
            <span className="rounded border border-purple-500/30 bg-purple-500/10 px-1.5 text-xs font-medium text-purple-400">DEMO DATA</span>
          )}
          {!assessment.confidence.complete && (
            <span className="rounded border border-yellow-500/30 bg-yellow-500/10 px-1.5 text-xs font-medium text-yellow-300">INCOMPLETE EVIDENCE</span>
          )}
        </div>
        <p className="mt-2 text-xs text-gray-400">{assessment.confidence.reasons[0]}</p>
        <p className="mt-1 text-[11px] text-gray-500">Policy: {assessment.confidence.policyVersion}</p>
      </div>

      <div className="space-y-6">
        {[...resolvedEdges].reverse().map(({ edge, resolved }, index) => (
          <article key={edge.id} className="text-sm">
            <div className="mb-1 text-xs font-medium text-gray-500">CLAIM {index + 1}</div>
            <div className="mb-2 break-words font-medium text-gray-200">
              {getNodeName(edge.sourceId)} <span className="mx-1 font-normal text-gray-500">DEPENDS_ON</span> {getNodeName(edge.targetId)}
            </div>

            {resolved.length > 0 ? (
              <ul className="space-y-2">
                {[...resolved].sort((a, b) => b.confidence - a.confidence).map((evidence) => (
                  <li key={evidence.id} className="flex gap-2 rounded border border-hydra-border/50 bg-hydra-bg p-2 text-sm">
                    <span className="text-emerald-500" aria-hidden="true">✓</span>
                    <div>
                      <div className="text-gray-300">Evidence resolved</div>
                      <div className="mt-0.5 text-xs text-gray-400">Source: {evidence.sourceType.replace(/-/g, ' ')}</div>
                      <div className="mt-0.5 text-xs text-gray-400">
                        Source confidence: <span className="text-emerald-400">{(evidence.confidence * 100).toFixed(0)}%</span>
                        {evidence.synthetic && <span className="ml-2 text-purple-400">DEMO</span>}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="flex items-center gap-1 text-xs italic text-gray-500"><span aria-hidden="true">○</span> Evidence ID did not resolve</div>
            )}
          </article>
        ))}

        <article className="border-t border-hydra-border/50 pt-2 text-sm">
          <div className="mb-1 text-xs font-medium text-gray-500">INCIDENT RELATION</div>
          <div className="flex gap-2">
            <span className="mt-0.5 text-emerald-500" aria-hidden="true">✓</span>
            <div className="text-gray-300">
              <span className="font-medium">{getNodeName(path.affectedVersionId)}</span> is a canonical AFFECTS target resolved for this incident.
            </div>
          </div>
          {incidentEvidence.length > 0 && (
            <ul className="mt-2 space-y-1 pl-5 text-xs text-gray-400">
              {incidentEvidence.map((evidence) => (
                <li key={evidence.id}>
                  {evidence.sourceType.replace(/-/g, ' ')} · {(evidence.confidence * 100).toFixed(0)}% source confidence{evidence.synthetic ? ' · DEMO' : ''}
                </li>
              ))}
            </ul>
          )}
        </article>

        <section className="pt-6" aria-labelledby="not-proven-heading">
          <div id="not-proven-heading" className="mb-2 text-xs font-medium text-gray-500">UNCERTAINTIES</div>
          <ul className="space-y-1 text-xs text-gray-500">
            {assessment.uncertainties.map((uncertainty) => (
              <li key={uncertainty}>— {uncertainty}</li>
            ))}
          </ul>
        </section>
      </div>
    </section>
  );
}

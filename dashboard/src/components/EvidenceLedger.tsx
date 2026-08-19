import type { BlastRadiusPath, EvidenceCatalogEntry, NodeId } from '../lib/api-types';

interface EvidenceLedgerProps {
  path: BlastRadiusPath;
  evidenceCatalog: readonly EvidenceCatalogEntry[];
  highConfidenceThreshold: number;
}

type PathState = 'missing' | 'verified' | 'high-confidence';

export function EvidenceLedger({
  path,
  evidenceCatalog,
  highConfidenceThreshold,
}: EvidenceLedgerProps) {
  const evidenceLookup = new Map<number, EvidenceCatalogEntry>();
  for (const evidence of evidenceCatalog) evidenceLookup.set(evidence.id, evidence);

  const resolvedEdges = path.canonicalEdges.map((edge) => ({
    edge,
    resolved: edge.evidenceIds
      .map((id) => evidenceLookup.get(id))
      .filter((evidence): evidence is EvidenceCatalogEntry => evidence !== undefined),
  }));

  const allEdgesHaveEvidence =
    resolvedEdges.length > 0 &&
    resolvedEdges.every(({ resolved }) => resolved.length > 0);

  const allEdgesHaveHighConfidenceEvidence =
    allEdgesHaveEvidence &&
    resolvedEdges.every(({ resolved }) =>
      resolved.some((evidence) => evidence.confidence >= highConfidenceThreshold),
    );

  let pathState: PathState = 'missing';
  let pathMessage = 'Structural candidate only. One or more canonical dependency claims lack resolved evidence.';

  if (allEdgesHaveHighConfidenceEvidence) {
    pathState = 'high-confidence';
    pathMessage = `Every canonical dependency claim has resolved evidence at or above ${(highConfidenceThreshold * 100).toFixed(0)}% confidence.`;
  } else if (allEdgesHaveEvidence) {
    pathState = 'verified';
    pathMessage = 'Every canonical dependency claim has at least one resolved evidence record.';
  }

  const hasSynthetic =
    path.nodes.some((node) =>
      node.synthetic || node.evidenceIds.some((id) => evidenceLookup.get(id)?.synthetic === true),
    ) ||
    resolvedEdges.some(({ resolved }) => resolved.some((evidence) => evidence.synthetic));

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
        <div className="mb-1 text-xs font-medium text-gray-400">PATH VERDICT</div>
        <div className="flex flex-wrap items-center gap-2">
          {pathState === 'high-confidence' && <span className="font-medium text-emerald-400">High-confidence evidence</span>}
          {pathState === 'verified' && <span className="font-medium text-amber-400">Evidence verified</span>}
          {pathState === 'missing' && <span className="font-medium text-gray-300">Structural candidate</span>}
          {hasSynthetic && <span className="rounded border border-purple-500/30 bg-purple-500/10 px-1.5 text-xs font-medium text-purple-400">DEMO DATA</span>}
        </div>
        <p className="mt-1 text-xs text-gray-400">{pathMessage}</p>
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
                {[...resolved].sort((a, b) => b.confidence - a.confidence).map((evidence) => {
                  const highConfidence = evidence.confidence >= highConfidenceThreshold;
                  return (
                    <li key={evidence.id} className="flex gap-2 rounded border border-hydra-border/50 bg-hydra-bg p-2 text-sm">
                      <span className={highConfidence ? 'text-emerald-500' : 'text-amber-400'} aria-hidden="true">✓</span>
                      <div>
                        <div className="text-gray-300">Evidence resolved</div>
                        <div className="mt-0.5 text-xs text-gray-400">Source: {evidence.sourceType.replace(/-/g, ' ')}</div>
                        <div className="mt-0.5 text-xs text-gray-400">
                          Confidence: <span className={highConfidence ? 'text-emerald-400' : 'text-amber-400'}>{(evidence.confidence * 100).toFixed(0)}%</span>
                          {evidence.synthetic && <span className="ml-2 text-purple-400">DEMO</span>}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <div className="flex items-center gap-1 text-xs italic text-gray-500"><span aria-hidden="true">○</span> No resolved evidence for this claim</div>
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
                  {evidence.sourceType.replace(/-/g, ' ')} · {(evidence.confidence * 100).toFixed(0)}% confidence{evidence.synthetic ? ' · DEMO' : ''}
                </li>
              ))}
            </ul>
          )}
        </article>

        <section className="pt-6" aria-labelledby="not-proven-heading">
          <div id="not-proven-heading" className="mb-2 text-xs font-medium text-gray-500">NOT PROVEN</div>
          <ul className="space-y-1 text-xs text-gray-500">
            <li>— Build inclusion</li>
            <li>— Deployment</li>
            <li>— Runtime reachability</li>
            <li>— Execution or compromise</li>
          </ul>
        </section>
      </div>
    </section>
  );
}

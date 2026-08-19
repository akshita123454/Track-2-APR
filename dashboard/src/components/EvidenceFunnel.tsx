import type { EvidenceFunnel as EvidenceFunnelType } from '../lib/api-types';

interface Props {
  funnel: EvidenceFunnelType;
}

export function EvidenceFunnel({ funnel }: Props) {
  const structural = funnel.stages.find(s => s.id === 'structural-candidate');
  const verified = funnel.stages.find(s => s.id === 'evidence-verified');
  const highConfidence = funnel.stages.find(s => s.id === 'high-confidence-evidence');

  if (!structural || !verified || !highConfidence) return null;

  const stages = [
    { stage: structural, color: 'text-gray-300',     bg: 'bg-gray-600/50',     border: 'border-gray-500' },
    { stage: verified,   color: 'text-amber-400',    bg: 'bg-amber-500/20',    border: 'border-amber-500/40' },
    { stage: highConfidence, color: 'text-emerald-400', bg: 'bg-emerald-500/20', border: 'border-emerald-500/40' },
  ];

  return (
    <div>
      {/* Flow row: Structural 12 → Evidence 7 → High confidence 3 */}
      <div className="flex items-center gap-3 mb-4">
        {stages.map(({ stage, color, bg, border }, i) => (
          <div key={stage.id} className="flex items-center gap-3">
            <div className={`${bg} border ${border} rounded-lg px-4 py-2.5`}>
              <div className={`text-xs font-medium ${color} tracking-wide`}>{stage.label}</div>
              <div className="flex items-baseline gap-2 mt-0.5">
                <span className={`text-xl font-bold ${color}`}>{stage.serviceCount}</span>
                <span className="text-xs text-gray-500">services</span>
                <span className="text-gray-600 mx-1">·</span>
                <span className={`text-lg font-semibold ${color}`}>{stage.pathCount}</span>
                <span className="text-xs text-gray-500">paths</span>
              </div>
            </div>
            {i < stages.length - 1 && (
              <svg className="w-6 h-6 text-gray-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            )}
          </div>
        ))}

        <div className="ml-auto text-xs text-gray-500">
          Threshold: <span className="text-gray-300 font-medium">{(funnel.highConfidenceThreshold * 100).toFixed(0)}%</span>
        </div>
      </div>

      {/* Claim boundary */}
      <div className="text-xs text-gray-500 border-t border-hydra-border pt-2 mt-1">
        A dependency path is a candidate impact path. It does not prove compromise or runtime execution.
      </div>
    </div>
  );
}

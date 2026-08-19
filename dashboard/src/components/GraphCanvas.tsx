import { useCallback, useMemo, useState } from 'react';
import type { LiveBlastRadiusResponse, NodeId } from '../lib/api-types';
import { GraphModel, type GraphModelEdge, type GraphModelNode } from '../lib/graph-model';

type GraphMode = 'dependency' | 'evidence';

interface GraphCanvasProps {
  data: LiveBlastRadiusResponse;
  selectedServiceId: number | null;
  selectedPathKey: string | null;
  onSelectService: (id: number) => void;
  onSelectPath: (key: string) => void;
}

const NODE_W = 170;
const NODE_H = 52;
const LAYER_GAP_Y = 110;
const NODE_GAP_X = 36;
const PAD_X = 60;
const PAD_Y = 40;

const EV_COLORS: Record<string, { fill: string; stroke: string; text: string }> = {
  missing: { fill: '#374151', stroke: '#6b7280', text: '#d1d5db' },
  verified: { fill: '#78350f', stroke: '#f59e0b', text: '#fde68a' },
  'high-confidence': { fill: '#064e3b', stroke: '#10b981', text: '#a7f3d0' },
};

function hexPath(cx: number, cy: number, radius: number): string {
  const points = Array.from({ length: 6 }, (_, index) => {
    const angle = (Math.PI / 3) * index - Math.PI / 6;
    return `${cx + radius * Math.cos(angle)},${cy + radius * Math.sin(angle)}`;
  });
  return `M${points.join('L')}Z`;
}

export function GraphCanvas({
  data,
  selectedServiceId,
  selectedPathKey,
  onSelectService,
  onSelectPath,
}: GraphCanvasProps) {
  const [mode, setMode] = useState<GraphMode>('dependency');
  const model = useMemo(() => new GraphModel(data), [data]);

  const { layerMap, maxLayer } = useMemo(() => {
    const layers = new Map<number, GraphModelNode[]>();
    let highestLayer = 0;

    for (const node of model.nodes.values()) {
      const layer = layers.get(node.layer) ?? [];
      layer.push(node);
      layers.set(node.layer, layer);
      highestLayer = Math.max(highestLayer, node.layer);
    }

    for (const nodes of layers.values()) nodes.sort((left, right) => left.id - right.id);
    return { layerMap: layers, maxLayer: highestLayer };
  }, [model]);

  const { nodePos, svgW, svgH } = useMemo(() => {
    const positions = new Map<NodeId, { x: number; y: number }>();
    let totalWidth = 0;

    for (let layer = 0; layer <= maxLayer; layer += 1) {
      const nodes = layerMap.get(layer) ?? [];
      totalWidth = Math.max(totalWidth, nodes.length * NODE_W + Math.max(0, nodes.length - 1) * NODE_GAP_X);
    }

    for (let layer = 0; layer <= maxLayer; layer += 1) {
      const nodes = layerMap.get(layer) ?? [];
      const rowWidth = nodes.length * NODE_W + Math.max(0, nodes.length - 1) * NODE_GAP_X;
      const offsetX = PAD_X + (totalWidth - rowWidth) / 2;

      nodes.forEach((node, index) => {
        positions.set(node.id, {
          x: offsetX + index * (NODE_W + NODE_GAP_X) + NODE_W / 2,
          y: PAD_Y + layer * LAYER_GAP_Y + NODE_H / 2,
        });
      });
    }

    return {
      nodePos: positions,
      svgW: totalWidth + PAD_X * 2,
      svgH: PAD_Y * 2 + (maxLayer + 1) * LAYER_GAP_Y,
    };
  }, [layerMap, maxLayer]);

  const selectedIds = useMemo(
    () => model.computeEmphasis(selectedServiceId, selectedPathKey),
    [model, selectedServiceId, selectedPathKey],
  );
  const hasSelection = selectedIds.nodeIds.size > 0;

  const selectNode = useCallback((node: GraphModelNode) => {
    if (node.type !== 'service') return;
    onSelectService(node.id);
    const firstPath = data.services.find(({ service }) => service.id === node.id)?.paths[0];
    if (firstPath) onSelectPath(firstPath.pathKey);
  }, [data.services, onSelectPath, onSelectService]);

  const nodeLabel = (node: GraphModelNode) => node.node.kind === 'Service' ? node.node.name : node.node.packageName;
  const nodeSubLabel = (node: GraphModelNode) => node.node.kind === 'PackageVersion' ? `v${node.node.version}` : null;

  const nodeColour = (node: GraphModelNode) => {
    if (mode === 'evidence') return EV_COLORS[node.evidenceState] ?? EV_COLORS.missing;
    if (node.type === 'affected-root') return { fill: '#7f1d1d', stroke: '#ef4444', text: '#fecaca' };
    if (node.type === 'service') return { fill: '#164e63', stroke: '#06b6d4', text: '#cffafe' };
    return { fill: '#1f2937', stroke: '#4b5563', text: '#d1d5db' };
  };

  const edgeColour = (edge: GraphModelEdge) =>
    mode === 'evidence' ? (EV_COLORS[edge.evidenceState] ?? EV_COLORS.missing).stroke : '#4b5563';

  return (
    <section className="relative h-full w-full overflow-auto bg-hydra-bg" aria-label="Blast-radius proof graph">
      <div className="absolute right-4 top-4 z-20 flex overflow-hidden rounded-lg border border-hydra-border bg-hydra-surface text-xs font-medium" aria-label="Graph display mode">
        <button
          type="button"
          onClick={() => setMode('dependency')}
          aria-pressed={mode === 'dependency'}
          className={`px-3 py-1.5 transition-colors ${mode === 'dependency' ? 'bg-hydra-accent/20 text-hydra-accent' : 'text-gray-400 hover:text-gray-200'}`}
        >Dependency Map</button>
        <button
          type="button"
          onClick={() => setMode('evidence')}
          aria-pressed={mode === 'evidence'}
          className={`px-3 py-1.5 transition-colors ${mode === 'evidence' ? 'bg-hydra-accent/20 text-hydra-accent' : 'text-gray-400 hover:text-gray-200'}`}
        >Evidence Mode</button>
      </div>

      <svg
        width={Math.max(svgW, 600)}
        height={Math.max(svgH, 400)}
        className="mx-auto"
        role="img"
        aria-labelledby="proof-graph-title proof-graph-description"
      >
        <title id="proof-graph-title">Candidate dependency proof graph</title>
        <desc id="proof-graph-description">Canonical dependency paths from services to incident-affected package versions. Select a service to inspect its evidence ledger.</desc>
        <defs>
          <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="context-stroke" />
          </marker>
          <filter id="glow"><feGaussianBlur stdDeviation="3" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
        </defs>

        {Array.from(model.edges.values()).map((edge) => {
          const from = nodePos.get(edge.sourceId);
          const to = nodePos.get(edge.targetId);
          if (!from || !to) return null;

          const selected = hasSelection && selectedIds.edgeIds.has(edge.id);
          const dimmed = hasSelection && !selected;
          const color = selected ? '#06b6d4' : edgeColour(edge);
          const downward = from.y < to.y;

          return (
            <line
              key={edge.id}
              x1={from.x}
              y1={from.y + (downward ? NODE_H / 2 : -NODE_H / 2)}
              x2={to.x}
              y2={to.y + (downward ? -NODE_H / 2 : NODE_H / 2)}
              stroke={color}
              strokeWidth={selected ? 2.5 : 1.5}
              strokeDasharray={mode === 'evidence' && edge.evidenceState === 'missing' ? '6 4' : undefined}
              opacity={dimmed ? 0.15 : 1}
              markerEnd="url(#arrowhead)"
              className="transition-opacity duration-300"
            />
          );
        })}

        {Array.from(model.nodes.values()).map((node) => {
          const position = nodePos.get(node.id);
          if (!position) return null;

          const dimmed = hasSelection && !selectedIds.nodeIds.has(node.id);
          const colours = nodeColour(node);
          const selected = node.id === selectedServiceId;
          const label = nodeLabel(node);
          const subLabel = nodeSubLabel(node);
          const interactive = node.type === 'service';
          const accessibleLabel = `${label}${subLabel ? ` ${subLabel}` : ''}, ${node.type.replace('-', ' ')}, ${node.evidenceState} evidence`;

          return (
            <g
              key={node.id}
              onClick={() => selectNode(node)}
              onKeyDown={(event) => {
                if (interactive && (event.key === 'Enter' || event.key === ' ')) {
                  event.preventDefault();
                  selectNode(node);
                }
              }}
              tabIndex={interactive ? 0 : undefined}
              role={interactive ? 'button' : undefined}
              aria-label={interactive ? accessibleLabel : undefined}
              className={`transition-opacity duration-300 ${interactive ? 'cursor-pointer' : 'cursor-default'}`}
              opacity={dimmed ? 0.2 : 1}
              filter={selected ? 'url(#glow)' : undefined}
            >
              <title>{accessibleLabel}</title>
              {node.type === 'affected-root' ? (
                <path d={hexPath(position.x, position.y, NODE_H / 2 + 4)} fill={colours.fill} stroke={colours.stroke} strokeWidth={2} />
              ) : (
                <rect
                  x={position.x - NODE_W / 2}
                  y={position.y - NODE_H / 2}
                  width={NODE_W}
                  height={NODE_H}
                  rx={node.type === 'service' ? 24 : 8}
                  fill={colours.fill}
                  stroke={selected ? '#06b6d4' : colours.stroke}
                  strokeWidth={selected ? 2.5 : 1.5}
                />
              )}

              {mode === 'evidence' && node.evidenceState === 'high-confidence' && (
                <rect x={position.x - NODE_W / 2 - 4} y={position.y - NODE_H / 2 - 4} width={NODE_W + 8} height={NODE_H + 8} rx={node.type === 'service' ? 28 : 12} fill="none" stroke="#10b981" strokeWidth={1.5} strokeDasharray="4 2" opacity={0.7} />
              )}

              <text x={position.x} y={position.y + (subLabel ? -4 : 2)} textAnchor="middle" fill={colours.text} fontSize="12" fontWeight="500" fontFamily="system-ui, sans-serif">
                {label.length > 20 ? `${label.slice(0, 18)}…` : label}
              </text>
              {subLabel && <text x={position.x} y={position.y + 12} textAnchor="middle" fill={colours.text} fontSize="10" opacity={0.7} fontFamily="system-ui, sans-serif">{subLabel}</text>}

              {node.type === 'affected-root' && <circle className="affected-pulse" cx={position.x + NODE_W / 2 - 8} cy={position.y - NODE_H / 2 + 4} r={5} fill="#ef4444" />}
              {node.synthetic && mode === 'evidence' && <text x={position.x} y={position.y + NODE_H / 2 + 14} textAnchor="middle" fill="#a855f7" fontSize="9" fontWeight="700" fontFamily="system-ui, sans-serif">DEMO</text>}
              {node.node.kind === 'Service' && node.node.criticality === 'critical' && <rect x={position.x - NODE_W / 2 - 6} y={position.y - NODE_H / 2 - 6} width={NODE_W + 12} height={NODE_H + 12} rx={30} fill="none" stroke="#ef4444" strokeWidth={1} opacity={0.5} />}
            </g>
          );
        })}
      </svg>
    </section>
  );
}

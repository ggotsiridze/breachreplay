import {
  Background,
  BackgroundVariant,
  type EdgeTypes,
  getViewportForBounds,
  type NodeTypes,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  useStore,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useCallback, useEffect, useMemo, useRef } from 'react';

import type { ReplayFrame } from '../replay/engine';
import { serviceNames } from '../components/ui';
import type { Selection } from '../stores/appStore';
import type { Incident } from '../types/incident';
import { AssetNode, type AssetFlowNode } from './AssetNode';
import { AttackEdge, type AttackFlowEdge } from './AttackEdge';
import { NODE_H, NODE_W } from './geometry';
import { layoutIncident } from './layout';

const nodeTypes: NodeTypes = { asset: AssetNode };
const edgeTypes: EdgeTypes = { attack: AttackEdge };

export interface IncidentGraphProps {
  incident: Incident;
  frame: ReplayFrame;
  view: 'focused' | 'all';
  selection: Selection;
  speed: number;
  autoFollow: boolean;
  onSelect: (sel: Selection) => void;
  fitSignal?: number;
}

function edgeLabel(protocols: string[], services: string[], ports: number[]): string {
  const svc = serviceNames(services);
  const proto = (protocols[0] ?? '').toUpperCase();
  const port = ports.length === 1 ? `${proto} ${ports[0]}` : ports.length ? `${proto} ${ports.slice(0, 2).join(', ')}${ports.length > 2 ? '…' : ''}` : proto;
  return [svc.slice(0, 2).join('/'), port].filter(Boolean).join(' · ');
}

function GraphInner({ incident, frame, view, selection, speed, autoFollow, onSelect, fitSignal }: IncidentGraphProps) {
  const layout = useMemo(() => layoutIncident(incident, view), [incident, view]);
  const flow = useReactFlow();
  const width = useStore((s) => s.width);
  const height = useStore((s) => s.height);
  const interacting = useRef(false);

  const highConfidenceAffected = useMemo(() => {
    const ids = new Set<string>();
    for (const e of incident.events)
      if (e.confidence_label === 'HIGH CONFIDENCE') for (const c of e.state_changes) if (c.to_state === 'AFFECTED') ids.add(c.asset_id);
    return ids;
  }, [incident]);

  const assetsById = useMemo(() => new Map(incident.assets.map((a) => [a.id, a])), [incident]);
  const pathSet = useMemo(() => new Set(incident.primary_attack_path), [incident]);
  const crownHitId = frame.crownJewelReached ? (frame.current?.event.event_type === 'crown_jewel_access' ? frame.current.event.destination_asset_id : null) : null;

  const nodes: AssetFlowNode[] = useMemo(
    () =>
      layout.visibleAssetIds.map((id) => {
        const asset = assetsById.get(id)!;
        const pos = layout.positions[id];
        const active = frame.activeAssetIds.includes(id);
        return {
          id,
          type: 'asset',
          position: { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 },
          width: NODE_W,
          height: NODE_H,
          draggable: true,
          selectable: true,
          data: {
            asset,
            state: frame.nodeStates[id] ?? 'NORMAL',
            active,
            selected: selection?.kind === 'asset' && selection.id === id,
            dimmed: view === 'focused' && frame.currentIndex >= 0 && !active && frame.nodeStates[id] === 'NORMAL' && !pathSet.has(id),
            onPath: pathSet.has(id),
            crownHit: crownHitId === id,
            highConfidence: highConfidenceAffected.has(id),
          },
        };
      }),
    [layout, assetsById, frame, selection, view, pathSet, crownHitId, highConfidenceAffected],
  );

  const edges: AttackFlowEdge[] = useMemo(() => {
    const byId = new Map(incident.edges.map((e) => [e.id, e]));
    return layout.visibleEdgeIds.map((id) => {
      const e = byId.get(id)!;
      return {
        id,
        source: e.source_asset_id,
        target: e.destination_asset_id,
        type: 'attack',
        zIndex: frame.activeEdgeIds.includes(id) ? 10 : 1,
        data: {
          visual: frame.edgeVisuals[id] ?? null,
          active: frame.activeEdgeIds.includes(id),
          blocked: frame.blockedEdgeIds.includes(id),
          selected: selection?.kind === 'edge' && selection.id === id,
          // Probe fans would repeat the same port label; the event card already names it.
          label: frame.current && frame.current.event.target_asset_ids.length > 1 ? '' : edgeLabel(e.protocols, e.services, e.ports),
          lane: layout.lanes[id] ?? 0,
          onPath: e.on_primary_path,
          speed,
        },
      };
    });
  }, [incident, layout, frame, selection, speed]);

  const fitAll = useCallback(() => {
    void flow.fitView({ padding: 0.18, duration: 600, maxZoom: 1.15 });
  }, [flow]);

  // Re-fit when the layout or container changes.
  useEffect(() => {
    interacting.current = false;
    const id = window.setTimeout(fitAll, 30);
    return () => window.clearTimeout(id);
  }, [fitAll, layout, width, height, fitSignal]);

  // Subtle follow: keep the whole incident framed, drift slightly toward the active systems.
  const currentId = frame.current?.event.id;
  useEffect(() => {
    if (!autoFollow || !currentId || interacting.current || !width || !height) return;
    const xs = layout.visibleAssetIds.map((id) => layout.positions[id]);
    if (!xs.length) return;
    const minX = Math.min(...xs.map((p) => p.x)) - NODE_W;
    const maxX = Math.max(...xs.map((p) => p.x)) + NODE_W;
    const minY = Math.min(...xs.map((p) => p.y)) - NODE_H * 2.4;
    const maxY = Math.max(...xs.map((p) => p.y)) + NODE_H * 1.4;
    const base = getViewportForBounds({ x: minX, y: minY, width: maxX - minX, height: maxY - minY }, width, height, 0.2, 1.15, 0.08);
    const active = frame.activeAssetIds.map((id) => layout.positions[id]).filter(Boolean);
    if (!active.length) return;
    const cx = active.reduce((s, p) => s + p.x, 0) / active.length;
    const cy = active.reduce((s, p) => s + p.y, 0) / active.length;
    const centreX = (minX + maxX) / 2;
    const centreY = (minY + maxY) / 2;
    const zoom = Math.min(base.zoom * 1.05, 1.2);
    const pull = 0.22;
    const fx = centreX + (cx - centreX) * pull;
    const fy = centreY + (cy - centreY) * pull;
    void flow.setViewport({ x: width / 2 - fx * zoom, y: height / 2 - fy * zoom, zoom }, { duration: 900 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentId, autoFollow, layout, width, height]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      minZoom={0.25}
      maxZoom={2}
      fitView
      fitViewOptions={{ padding: 0.18, maxZoom: 1.15 }}
      nodesConnectable={false}
      elementsSelectable
      onMoveStart={(e) => {
        if (e) interacting.current = true;
      }}
      onNodeClick={(_, node) => onSelect({ kind: 'asset', id: node.id })}
      onEdgeClick={(_, edge) => onSelect({ kind: 'edge', id: edge.id })}
      onPaneClick={() => onSelect(null)}
      proOptions={{ hideAttribution: false }}
      className="br-flow"
    >
      <Background variant={BackgroundVariant.Dots} gap={28} size={1.1} color="rgba(148, 163, 184, 0.16)" />
    </ReactFlow>
  );
}

export function IncidentGraph(props: IncidentGraphProps) {
  return (
    <ReactFlowProvider>
      <GraphInner {...props} />
    </ReactFlowProvider>
  );
}

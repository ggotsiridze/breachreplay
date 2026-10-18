import type { Edge, EdgeProps } from '@xyflow/react';
import { memo, useMemo } from 'react';

import type { EdgeVisual } from '../replay/engine';
import { curvePath, edgeCurve, pointAt, splitCurve, tangentAngle } from './geometry';

export type AttackEdgeData = {
  visual: EdgeVisual | null;
  active: boolean;
  blocked: boolean;
  selected: boolean;
  label: string;
  lane: number;
  onPath: boolean;
  speed: number;
};

export type AttackFlowEdge = Edge<AttackEdgeData, 'attack'>;

const BLOCK_AT = 0.56;

function AttackEdgeView({ id, sourceX, sourceY, targetX, targetY, data }: EdgeProps<AttackFlowEdge>) {
  const d = data as AttackEdgeData;
  const curve = useMemo(() => edgeCurve({ x: sourceX, y: sourceY }, { x: targetX, y: targetY }, d.lane), [sourceX, sourceY, targetX, targetY, d.lane]);
  const path = curvePath(curve);
  // animateMotion offsets the element's own position, so the motion path is relative to the start point.
  const motionPath = curvePath({
    start: { x: 0, y: 0 },
    c1: { x: curve.c1.x - curve.start.x, y: curve.c1.y - curve.start.y },
    c2: { x: curve.c2.x - curve.start.x, y: curve.c2.y - curve.start.y },
    end: { x: curve.end.x - curve.start.x, y: curve.end.y - curve.start.y },
  });
  const visual = d.visual;
  const cls = ['br-edge', visual ? `is-${visual}` : 'is-ghost', d.active ? 'is-active' : '', d.blocked ? 'is-blocked' : '', d.selected ? 'is-selected' : '', d.onPath ? 'is-path' : '']
    .filter(Boolean)
    .join(' ');
  const mid = pointAt(curve, 0.5);
  const stop = pointAt(curve, BLOCK_AT);
  const endAngle = tangentAngle(curve, 0.985);
  const tip = curve.end;
  const packetDur = `${Math.max(0.7, 1.6 - Math.min(d.speed, 10) * 0.06).toFixed(2)}s`;

  return (
    <g className={cls} data-testid={`edge-${id}`} data-visual={visual ?? 'ghost'} data-active={d.active ? 'true' : 'false'} data-blocked={d.blocked ? 'true' : 'false'}>
      <path className="br-edge-hit" d={path} />
      {d.blocked ? (
        <>
          <path className="br-edge-line br-edge-pre" d={curvePath(splitCurve(curve, BLOCK_AT)[0])} />
          <path className="br-edge-line br-edge-post" d={curvePath(splitCurve(curve, BLOCK_AT)[1])} />
          <g transform={`translate(${stop.x} ${stop.y})`} className="br-edge-block">
            <circle r="15" />
            <path d="M-5.5 -5.5 L5.5 5.5 M5.5 -5.5 L-5.5 5.5" />
          </g>
        </>
      ) : (
        <>
          {d.active && <path className="br-edge-glow" d={path} />}
          <path className="br-edge-line" d={path} />
          {visual && (
            <path
              className="br-edge-arrow"
              d="M -9 -5 L 1 0 L -9 5 z"
              transform={`translate(${tip.x} ${tip.y}) rotate(${endAngle})`}
            />
          )}
          {d.active && (
            <>
              {/* cx/cy: where the packet sits before the SMIL animation starts */}
              <circle className="br-edge-packet-trail" r="9" cx={curve.start.x} cy={curve.start.y}>
                <animateMotion dur={packetDur} repeatCount="indefinite" path={motionPath} />
              </circle>
              <circle className="br-edge-packet" r="4.2" cx={curve.start.x} cy={curve.start.y}>
                <animateMotion dur={packetDur} repeatCount="indefinite" path={motionPath} />
              </circle>
            </>
          )}
        </>
      )}
      {(d.active || d.selected || d.blocked) && d.label && (
        <foreignObject x={mid.x - 80} y={mid.y - 14} width={160} height={28} className="br-edge-label-wrap" requiredExtensions="http://www.w3.org/1999/xhtml">
          <div className={`br-edge-label ${d.blocked ? 'is-blocked' : ''}`}>{d.blocked ? 'CONTAINMENT' : d.label}</div>
        </foreignObject>
      )}
    </g>
  );
}

export const AttackEdge = memo(AttackEdgeView);

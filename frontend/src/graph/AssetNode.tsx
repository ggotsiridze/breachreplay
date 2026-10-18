import { Handle, type Node, type NodeProps, Position } from '@xyflow/react';
import { memo } from 'react';

import type { Asset, AssetState } from '../types/incident';
import { AssetIcon, CrownIcon, ShieldIcon } from './icons';

export type AssetNodeData = {
  asset: Asset;
  state: AssetState;
  active: boolean;
  selected: boolean;
  dimmed: boolean;
  onPath: boolean;
  crownHit: boolean;
  highConfidence: boolean;
};

export type AssetFlowNode = Node<AssetNodeData, 'asset'>;

const STATE_TEXT: Record<AssetState, string> = {
  NORMAL: 'Normal',
  SUSPICIOUS: 'Suspicious',
  AFFECTED: 'Affected',
  CONTAINED: 'Contained',
  PROTECTED: 'Protected',
};

function AssetNodeView({ data }: NodeProps<AssetFlowNode>) {
  const { asset, state, active, selected, dimmed, crownHit, highConfidence } = data;
  const external = asset.asset_type === 'INTERNET';
  const stateLabel = STATE_TEXT[state];
  return (
    <div
      className={[
        'br-node',
        `is-${state.toLowerCase()}`,
        external ? 'is-external' : '',
        asset.crown_jewel ? 'is-crown' : '',
        active ? 'is-active' : '',
        selected ? 'is-selected' : '',
        dimmed ? 'is-dimmed' : '',
        crownHit ? 'is-crown-hit' : '',
      ].join(' ')}
      data-testid={`node-${asset.id}`}
      data-state={state}
      data-high-confidence={highConfidence && state === 'AFFECTED' ? 'true' : undefined}
      aria-label={`${asset.display_name}, ${asset.role}, state ${stateLabel}${highConfidence && state === 'AFFECTED' ? ' (high confidence)' : ''}`}
    >
      <Handle type="target" position={Position.Left} className="br-handle" isConnectable={false} />
      <Handle type="source" position={Position.Right} className="br-handle" isConnectable={false} />
      {asset.crown_jewel && (
        <div className="br-node-crown">
          <CrownIcon size={12} /> Crown jewel
        </div>
      )}
      <div className="br-node-ring" />
      <div className="br-node-icon">
        <AssetIcon type={asset.asset_type} crown={asset.crown_jewel} size={22} />
      </div>
      <div className="br-node-text">
        <div className="br-node-name">{external ? 'INTERNET' : asset.display_name}</div>
        <div className="br-node-role">{external ? asset.ip : asset.role}</div>
      </div>
      <div className="br-node-state">
        {(state === 'CONTAINED' || state === 'PROTECTED') && <ShieldIcon size={11} />}
        <span className="br-node-dot" />
        {stateLabel}
      </div>
    </div>
  );
}

export const AssetNode = memo(AssetNodeView);

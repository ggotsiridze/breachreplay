import { render } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { Position } from '@xyflow/react';

import { AttackEdge, type AttackEdgeData } from './AttackEdge';

const base: AttackEdgeData = { visual: 'attack', active: false, blocked: false, selected: false, label: 'SMB · TCP 445', lane: 0, onPath: true, speed: 5 };

function renderEdge(data: Partial<AttackEdgeData>) {
  const props = {
    id: 'edge-a--b',
    source: 'a',
    target: 'b',
    sourceX: 0,
    sourceY: 0,
    targetX: 300,
    targetY: 0,
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    data: { ...base, ...data },
  } as unknown as ComponentProps<typeof AttackEdge>;
  return render(
    <svg>
      <AttackEdge {...props} />
    </svg>,
  );
}

describe('AttackEdge', () => {
  it('renders an animated packet only while active', () => {
    const idle = renderEdge({});
    expect(idle.container.querySelector('.br-edge-packet')).toBeNull();
    idle.unmount();
    const active = renderEdge({ active: true });
    expect(active.container.querySelector('.br-edge-packet animateMotion')).not.toBeNull();
    expect(active.getByText('SMB · TCP 445')).toBeInTheDocument();
    expect(active.container.querySelector('[data-active="true"]')).not.toBeNull();
  });

  it('draws a containment marker when blocked', () => {
    const { container, getByText } = renderEdge({ blocked: true });
    expect(container.querySelector('.br-edge-block')).not.toBeNull();
    expect(container.querySelectorAll('.br-edge-line').length).toBe(2);
    expect(getByText('CONTAINMENT')).toBeInTheDocument();
  });

  it('is a faint ghost before it is revealed', () => {
    const { container } = renderEdge({ visual: null });
    expect(container.querySelector('[data-visual="ghost"]')).not.toBeNull();
    expect(container.querySelector('.br-edge-arrow')).toBeNull();
  });
});

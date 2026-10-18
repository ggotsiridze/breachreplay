import { incident, simulation } from '../test/fixtures';
import { LEAD_SECONDS, buildTimeline, edgeId, formatOffset, frameAt, nextEventAt, previousEventAt } from './engine';

const ids = incident.assets.map((a) => a.id);

describe('replay timeline', () => {
  const tl = buildTimeline(incident);

  it('orders events chronologically with offsets relative to the incident start', () => {
    const at = tl.events.map((e) => e.at);
    expect(at).toEqual([...at].sort((a, b) => a - b));
    expect(tl.events[0].at).toBeCloseTo(LEAD_SECONDS, 5);
    expect(tl.duration).toBeGreaterThan(tl.events[tl.events.length - 1].at);
  });

  it('1x corresponds to real elapsed time between events', () => {
    const lateral = tl.events.find((e) => e.event.event_type === 'lateral_movement')!;
    const crown = tl.events.find((e) => e.event.event_type === 'crown_jewel_access')!;
    expect(crown.at - lateral.at).toBeCloseTo(crown.event.timestamp - lateral.event.timestamp, 6);
  });

  it('builds phases in order', () => {
    expect(tl.phases.map((p) => p.phase)).toEqual(['Reconnaissance', 'Initial Access', 'Command and Control', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration']);
  });

  it('starts with every asset normal and no current event', () => {
    const f = frameAt(tl, ids, 0);
    expect(f.current).toBeNull();
    expect(Object.values(f.nodeStates).every((s) => s === 'NORMAL')).toBe(true);
    expect(f.phase).toBe('Baseline');
    expect(f.crownJewelReached).toBe(false);
  });

  it('applies state transitions, active edge and phase at the lateral movement', () => {
    const lateral = tl.events.find((e) => e.event.event_type === 'lateral_movement')!;
    const f = frameAt(tl, ids, lateral.at + 0.5);
    expect(f.current?.event.id).toBe(lateral.event.id);
    expect(f.phase).toBe('Lateral Movement');
    expect(f.nodeStates['asset-ws-03']).toBe('AFFECTED');
    expect(f.nodeStates['asset-web-01']).toBe('AFFECTED');
    expect(f.nodeStates['asset-db-01']).toBe('NORMAL');
    expect(f.activeEdgeIds).toEqual([edgeId('asset-web-01', 'asset-ws-03')]);
    expect(f.edgeVisuals[edgeId('asset-web-01', 'asset-ws-03')]).toBe('attack');
  });

  it('marks the crown jewel reached only after the crown-jewel event', () => {
    const crown = tl.events.find((e) => e.event.event_type === 'crown_jewel_access')!;
    expect(frameAt(tl, ids, crown.at - 0.1).crownJewelReached).toBe(false);
    const f = frameAt(tl, ids, crown.at + 0.1);
    expect(f.crownJewelReached).toBe(true);
    expect(f.nodeStates['asset-db-01']).toBe('AFFECTED');
  });

  it('is deterministic when seeking backwards and forwards', () => {
    const end = frameAt(tl, ids, tl.duration);
    const early = frameAt(tl, ids, 5);
    const again = frameAt(tl, ids, tl.duration);
    expect(again).toEqual(end);
    expect(early.nodeStates['asset-ws-03']).toBe('NORMAL');
  });

  it('clamps out-of-range times', () => {
    expect(frameAt(tl, ids, -50).t).toBe(0);
    expect(frameAt(tl, ids, 1e9).t).toBe(tl.duration);
  });

  it('marks discovery edges as probes, not traversal', () => {
    const disc = tl.events.find((e) => e.event.event_type === 'discovery')!;
    const f = frameAt(tl, ids, disc.at + 0.1);
    expect(f.activeEdgeIds.length).toBe(4);
    expect(f.edgeVisuals[edgeId('asset-web-01', 'asset-ws-01')]).toBe('probe');
  });

  it('steps between events', () => {
    const first = tl.events[0].at;
    expect(nextEventAt(tl, 0)).toBeCloseTo(first);
    expect(previousEventAt(tl, tl.events[2].at)).toBeCloseTo(tl.events[1].at);
    expect(nextEventAt(tl, tl.duration)).toBeNull();
  });

  it('formats offsets', () => {
    expect(formatOffset(0)).toBe('00:00');
    expect(formatOffset(107.9)).toBe('01:47');
  });
});

describe('simulated timeline', () => {
  const tl = buildTimeline(incident, simulation);

  it('carries outcomes from the simulation result', () => {
    expect(tl.scenario).toBe('simulated');
    const outcome = Object.fromEntries(tl.events.map((e) => [e.event.id, e.outcome]));
    expect(outcome['evt-05']).toBe('INTERRUPTED');
    expect(outcome['evt-06']).toBe('NOT_REACHED');
  });

  it('blocks the interrupted edge and protects downstream assets', () => {
    const f = frameAt(tl, ids, tl.duration);
    expect(f.blockedEdgeIds).toContain(edgeId('asset-web-01', 'asset-ws-03'));
    expect(f.nodeStates['asset-ws-03']).toBe('CONTAINED');
    expect(f.nodeStates['asset-db-01']).toBe('PROTECTED');
    expect(f.crownJewelReached).toBe(false);
    expect(f.interrupted).toBe(true);
  });

  it('never makes an unreached step the current event', () => {
    const f = frameAt(tl, ids, tl.duration);
    expect(f.current?.outcome).not.toBe('NOT_REACHED');
    expect(f.phase).toBe('Lateral Movement');
  });

  it('shows the observed path unchanged before the control activates', () => {
    const initial = tl.events.find((e) => e.event.event_type === 'initial_access')!;
    const f = frameAt(tl, ids, initial.at + 0.1);
    expect(f.nodeStates['asset-web-01']).toBe('AFFECTED');
    expect(f.nodeStates['asset-ws-03']).toBe('NORMAL');
  });
});

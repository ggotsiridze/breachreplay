import { incident } from '../test/fixtures';
import { COL, focusedAssetIds, layoutIncident } from './layout';

describe('incident layout', () => {
  it('lays the primary attack path left to right on one row', () => {
    const { positions } = layoutIncident(incident, 'focused');
    const path = incident.primary_attack_path.map((id) => positions[id]);
    path.forEach((p, i) => {
      expect(p.y).toBe(0);
      expect(p.x).toBe(i * COL);
    });
  });

  it('focused view shows only incident assets and incident edges', () => {
    const r = layoutIncident(incident, 'focused');
    expect(new Set(r.visibleAssetIds)).toEqual(focusedAssetIds(incident));
    expect(r.visibleAssetIds).not.toContain('asset-dns-01');
    const edges = new Map(incident.edges.map((e) => [e.id, e]));
    expect(r.visibleEdgeIds.every((id) => edges.get(id)!.event_ids.length > 0)).toBe(true);
  });

  it('all view shows every observed asset and connection', () => {
    const r = layoutIncident(incident, 'all');
    expect(r.visibleAssetIds.length).toBe(incident.assets.length);
    expect(r.visibleEdgeIds.length).toBe(incident.edges.length);
  });

  it('never stacks two assets on the same spot', () => {
    for (const view of ['focused', 'all'] as const) {
      const { positions, visibleAssetIds } = layoutIncident(incident, view);
      const keys = visibleAssetIds.map((id) => `${positions[id].x},${positions[id].y}`);
      expect(new Set(keys).size).toBe(keys.length);
    }
  });

  it('places probed siblings below the path asset that shares the discovery event', () => {
    const { positions } = layoutIncident(incident, 'focused');
    for (const id of ['asset-ws-01', 'asset-ws-02', 'asset-10-20-2-34']) {
      expect(positions[id].x).toBe(positions['asset-ws-03'].x);
      expect(positions[id].y).toBeGreaterThan(0);
    }
  });

  it('gives backward outbound arcs separate lanes', () => {
    const { lanes } = layoutIncident(incident, 'focused');
    expect(lanes['edge-web-01--203-0-113-45']).toBe(0);
    expect(lanes['edge-ws-03--203-0-113-45']).toBe(1);
  });
});

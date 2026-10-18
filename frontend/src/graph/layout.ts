/**
 * Deterministic incident layout.
 *
 * The primary attack path runs left to right along the centre line, which is
 * what makes the story readable at a glance. Other assets are placed in the
 * column of the path asset they relate to: probed siblings stack under the
 * path asset that shares their discovery event, external peers sit above,
 * internal peers below.
 */
import type { Incident } from '../types/incident';

export const COL = 300;
export const ROW = 132;

export interface LayoutResult {
  positions: Record<string, { x: number; y: number }>;
  visibleAssetIds: string[];
  visibleEdgeIds: string[];
  lanes: Record<string, number>;
}

export function focusedAssetIds(incident: Incident): Set<string> {
  const ids = new Set<string>(incident.primary_attack_path);
  for (const e of incident.events) {
    if (e.source_asset_id) ids.add(e.source_asset_id);
    for (const t of e.target_asset_ids) ids.add(t);
    if (e.destination_asset_id) ids.add(e.destination_asset_id);
  }
  return ids;
}

export function layoutIncident(incident: Incident, view: 'focused' | 'all'): LayoutResult {
  const visible = view === 'all' || !incident.incident_found ? new Set(incident.assets.map((a) => a.id)) : focusedAssetIds(incident);
  const assets = incident.assets.filter((a) => visible.has(a.id));
  const byId = new Map(assets.map((a) => [a.id, a]));
  const positions: Record<string, { x: number; y: number }> = {};
  const column: Record<string, number> = {};
  const used = new Map<number, Set<number>>();

  const occupy = (col: number, row: number) => {
    if (!used.has(col)) used.set(col, new Set());
    used.get(col)!.add(row);
  };
  const place = (id: string, col: number, row: number) => {
    column[id] = col;
    positions[id] = { x: col * COL, y: row * ROW };
    occupy(col, row);
  };
  const freeRow = (col: number, preferAbove: boolean): number => {
    const taken = used.get(col) ?? new Set<number>();
    // Internal assets stack below the path, external ones above it: the space
    // directly above the path is where backward (outbound) arcs are drawn.
    for (let k = 1; k < 50; k++) {
      const r = preferAbove ? -k : k;
      if (!taken.has(r)) return r;
    }
    return preferAbove ? -50 : 50;
  };

  // 1. The primary path, left to right.
  const path = incident.primary_attack_path.filter((id) => byId.has(id));
  path.forEach((id, i) => place(id, i, 0));

  // 2. Without a path, layer by first-seen order of initiators.
  if (path.length === 0) {
    const sorted = [...assets].sort((a, b) => Number(a.internal) - Number(b.internal) || a.first_seen - b.first_seen || a.id.localeCompare(b.id));
    const perCol = Math.max(3, Math.ceil(Math.sqrt(sorted.length)));
    sorted.forEach((a, i) => place(a.id, Math.floor(i / perCol), (i % perCol) - Math.floor(perCol / 2)));
  }

  // Sibling relation: assets probed by the same discovery event as a path asset.
  const sibling = new Map<string, string>();
  for (const e of incident.events) {
    if (e.target_asset_ids.length < 2) continue;
    const anchor = e.target_asset_ids.find((t) => path.includes(t));
    if (anchor) for (const t of e.target_asset_ids) if (t !== anchor) sibling.set(t, anchor);
  }

  const neighbours = new Map<string, { id: string; outgoing: boolean }[]>();
  for (const edge of incident.edges) {
    if (!byId.has(edge.source_asset_id) || !byId.has(edge.destination_asset_id)) continue;
    neighbours.set(edge.destination_asset_id, [...(neighbours.get(edge.destination_asset_id) ?? []), { id: edge.source_asset_id, outgoing: false }]);
    neighbours.set(edge.source_asset_id, [...(neighbours.get(edge.source_asset_id) ?? []), { id: edge.destination_asset_id, outgoing: true }]);
  }

  // 3. Remaining assets, most important / earliest first, over several passes.
  const remaining = assets
    .filter((a) => positions[a.id] === undefined)
    .sort((a, b) => b.importance - a.importance || a.first_seen - b.first_seen || a.id.localeCompare(b.id));
  for (let pass = 0; pass < 4 && remaining.length; pass++) {
    for (let i = 0; i < remaining.length; ) {
      const a = remaining[i];
      let col: number | undefined;
      const sib = sibling.get(a.id);
      if (sib !== undefined && column[sib] !== undefined) col = column[sib];
      if (col === undefined) {
        const cols = (neighbours.get(a.id) ?? [])
          .filter((n) => column[n.id] !== undefined)
          .map((n) => (n.outgoing ? column[n.id] : column[n.id] + (byId.get(n.id)?.internal ? 0.5 : 1)));
        if (cols.length) {
          cols.sort((x, y) => x - y);
          col = Math.round(cols[Math.floor(cols.length / 2)]);
        }
      }
      if (col === undefined && pass < 3) {
        i++;
        continue;
      }
      col = col ?? 0;
      place(a.id, col, freeRow(col, !a.internal));
      remaining.splice(i, 1);
    }
  }

  const visibleEdges = incident.edges.filter(
    (e) =>
      byId.has(e.source_asset_id) &&
      byId.has(e.destination_asset_id) &&
      (view === 'all' || !incident.incident_found || e.event_ids.length > 0 || e.on_primary_path),
  );

  // Lanes separate several backward arcs that share a row.
  const lanes: Record<string, number> = {};
  let backward = 0;
  for (const e of [...visibleEdges].sort((a, b) => a.first_seen - b.first_seen)) {
    const s = positions[e.source_asset_id];
    const t = positions[e.destination_asset_id];
    if (t.x < s.x - 40 && Math.abs(t.y - s.y) < 80) lanes[e.id] = backward++;
    else lanes[e.id] = 0;
  }

  return { positions, visibleAssetIds: assets.map((a) => a.id), visibleEdgeIds: visibleEdges.map((e) => e.id), lanes };
}

/**
 * Deterministic replay engine.
 *
 * Everything the replay shows at time t is a pure function of the incident
 * (or a simulation result) and t. Seeking is therefore exact: there is no
 * accumulated animation state to get out of sync.
 */
import type {
  AssetState,
  ControlActivation,
  EventOutcome,
  Incident,
  IncidentEvent,
  SimulationResult,
  StateChange,
} from '../types/incident';

export const LEAD_SECONDS = 3;
export const TAIL_SECONDS = 4;

export type EdgeVisual = 'attack' | 'suspicious' | 'probe' | 'observed';

export interface TimelineEvent {
  event: IncidentEvent;
  at: number;
  outcome: EventOutcome;
  changes: StateChange[];
  edgeIds: string[];
  visual: EdgeVisual;
}

export interface TimelineActivation extends ControlActivation {
  at: number;
}

export interface Timeline {
  scenario: 'observed' | 'simulated';
  start: number;
  duration: number;
  events: TimelineEvent[];
  activations: TimelineActivation[];
  phases: { phase: string; from: number; to: number }[];
  interruptionAt: number | null;
  protectedAssets: string[];
  crownJewels: string[];
}

export interface ReplayFrame {
  t: number;
  clock: number;
  currentIndex: number;
  current: TimelineEvent | null;
  activeEdgeIds: string[];
  edgeVisuals: Record<string, EdgeVisual>;
  blockedEdgeIds: string[];
  nodeStates: Record<string, AssetState>;
  phase: string;
  crownJewelReached: boolean;
  crownJewelEventIndex: number;
  interrupted: boolean;
  activeAssetIds: string[];
  counters: { events: number; affected: number; suspicious: number; contained: number; protected: number };
}

const STATE_RANK: Record<AssetState, number> = { NORMAL: 0, SUSPICIOUS: 1, AFFECTED: 2, CONTAINED: 3, PROTECTED: 3 };

export function edgeId(src: string, dst: string): string {
  return `edge-${src.replace(/^asset-/, '')}--${dst.replace(/^asset-/, '')}`;
}

export function eventEdgeIds(event: IncidentEvent, knownEdges: Set<string>): string[] {
  if (!event.source_asset_id) return [];
  const targets = event.target_asset_ids.length ? event.target_asset_ids : event.destination_asset_id ? [event.destination_asset_id] : [];
  return targets.map((t) => edgeId(event.source_asset_id as string, t)).filter((id) => knownEdges.has(id));
}

function visualFor(event: IncidentEvent): EdgeVisual {
  if (event.event_type === 'discovery') return 'probe';
  if (event.confidence_label === 'LIKELY' || event.confidence_label === 'HIGH CONFIDENCE') return 'attack';
  if (event.confidence_label === 'SUSPICIOUS') return 'suspicious';
  return 'observed';
}

export function buildTimeline(incident: Incident, simulation?: SimulationResult | null): Timeline {
  const startedAt = incident.started_at ?? incident.capture_started_at ?? 0;
  const endedAt = incident.ended_at ?? startedAt;
  const start = startedAt - LEAD_SECONDS;
  const duration = Math.max(1, endedAt - startedAt + LEAD_SECONDS + TAIL_SECONDS);
  const known = new Set(incident.edges.map((e) => e.id));
  const outcomes = new Map((simulation?.event_outcomes ?? []).map((o) => [o.event_id, o]));
  const events: TimelineEvent[] = [...incident.events]
    .sort((a, b) => a.timestamp - b.timestamp || a.id.localeCompare(b.id))
    .map((event) => {
      const sim = outcomes.get(event.id);
      return {
        event,
        at: event.timestamp - start,
        outcome: sim ? sim.outcome : 'OCCURRED',
        changes: sim ? sim.state_changes : event.state_changes,
        edgeIds: eventEdgeIds(event, known),
        visual: visualFor(event),
      };
    });
  const phases: Timeline['phases'] = [];
  for (const te of events) {
    if (te.event.confidence_label === 'OBSERVED' && te.event.event_type !== 'external_recon') continue;
    const last = phases[phases.length - 1];
    if (last && last.phase === te.event.phase) continue;
    if (last) last.to = te.at;
    phases.push({ phase: te.event.phase, from: te.at, to: duration });
  }
  const activations = (simulation?.activations ?? []).map((a) => ({ ...a, at: Math.max(0, a.timestamp - start) }));
  const interruption = simulation?.interrupted_at != null ? simulation.interrupted_at - start : null;
  return {
    scenario: simulation ? 'simulated' : 'observed',
    start,
    duration,
    events,
    activations,
    phases,
    interruptionAt: interruption,
    protectedAssets: simulation?.protected_assets ?? [],
    crownJewels: incident.crown_jewels,
  };
}

export function frameAt(timeline: Timeline, assetIds: string[], rawT: number): ReplayFrame {
  const t = Math.min(Math.max(rawT, 0), timeline.duration);
  const nodeStates: Record<string, AssetState> = {};
  for (const id of assetIds) nodeStates[id] = 'NORMAL';

  const edgeVisuals: Record<string, EdgeVisual> = {};
  const blocked: string[] = [];
  let currentIndex = -1;
  let crownJewelEventIndex = -1;
  const crown = new Set(timeline.crownJewels);

  const contained = new Set<string>();
  for (const act of timeline.activations) {
    if (act.at <= t) for (const a of act.contained_asset_ids) contained.add(a);
  }

  timeline.events.forEach((te, i) => {
    if (te.at > t) return;
    // Steps the simulated attacker never reached do not become the current event.
    if (te.outcome !== 'NOT_REACHED') currentIndex = i;
    if (te.outcome === 'OCCURRED') {
      for (const id of te.edgeIds) {
        const prev = edgeVisuals[id];
        if (!prev || rankVisual(te.visual) > rankVisual(prev)) edgeVisuals[id] = te.visual;
      }
      for (const ch of te.changes) {
        const cur = nodeStates[ch.asset_id] ?? 'NORMAL';
        if (STATE_RANK[ch.to_state] > STATE_RANK[cur]) nodeStates[ch.asset_id] = ch.to_state;
      }
      if (
        te.event.event_type === 'crown_jewel_access' &&
        te.event.destination_asset_id &&
        crown.has(te.event.destination_asset_id) &&
        te.event.confidence_label !== 'OBSERVED' &&
        crownJewelEventIndex < 0
      ) {
        crownJewelEventIndex = i;
      }
    } else if (te.outcome === 'INTERRUPTED') {
      blocked.push(...te.edgeIds);
    }
  });

  for (const a of contained) nodeStates[a] = 'CONTAINED';
  const interrupted = timeline.interruptionAt !== null && t >= timeline.interruptionAt;
  if (interrupted) for (const a of timeline.protectedAssets) if (!contained.has(a)) nodeStates[a] = 'PROTECTED';

  const current = currentIndex >= 0 ? timeline.events[currentIndex] : null;
  const activeEdgeIds = current && current.outcome === 'OCCURRED' ? current.edgeIds : [];
  const activeAssetIds = current
    ? [current.event.source_asset_id, ...(current.event.target_asset_ids.length ? current.event.target_asset_ids : [current.event.destination_asset_id])].filter(
        (x): x is string => Boolean(x),
      )
    : [];
  const states = Object.values(nodeStates);
  return {
    t,
    clock: timeline.start + t,
    currentIndex,
    current,
    activeEdgeIds,
    edgeVisuals,
    blockedEdgeIds: blocked,
    nodeStates,
    phase: current ? current.event.phase : 'Baseline',
    crownJewelReached: crownJewelEventIndex >= 0,
    crownJewelEventIndex,
    interrupted,
    activeAssetIds,
    counters: {
      events: currentIndex + 1,
      affected: states.filter((s) => s === 'AFFECTED').length,
      suspicious: states.filter((s) => s === 'SUSPICIOUS').length,
      contained: states.filter((s) => s === 'CONTAINED').length,
      protected: states.filter((s) => s === 'PROTECTED').length,
    },
  };
}

function rankVisual(v: EdgeVisual): number {
  return { observed: 0, probe: 1, suspicious: 2, attack: 3 }[v];
}

/** Time of the next/previous event relative to t (for step controls). */
export function nextEventAt(timeline: Timeline, t: number): number | null {
  const next = timeline.events.find((e) => e.at > t + 1e-6);
  return next ? next.at : null;
}

export function previousEventAt(timeline: Timeline, t: number): number | null {
  const prev = [...timeline.events].reverse().find((e) => e.at < t - 0.05);
  return prev ? prev.at : null;
}

export function formatOffset(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
}

export function formatClock(epochSeconds: number): string {
  const d = new Date(epochSeconds * 1000);
  return d.toISOString().slice(11, 19);
}

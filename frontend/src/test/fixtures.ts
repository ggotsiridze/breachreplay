import showcase from '../../../showcase/showcase-incident.json';
import simulationJson from './fixtures/simulation-isolate-ws03.json';
import type { Incident, NetworkEvidence, SimulationResult } from '../types/incident';

/** The real showcase incident exported from the full Zeek + Suricata pipeline. */
export const incident = showcase.incident as unknown as Incident;
export const evidence = showcase.evidence as unknown as NetworkEvidence[];
/** A real simulation response (isolate WS-03 at first detection) recorded from the API. */
export const simulation = simulationJson as unknown as SimulationResult;

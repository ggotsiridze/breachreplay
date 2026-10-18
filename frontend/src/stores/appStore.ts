import { create } from 'zustand';

import { ApiError, api, watchAnalysis } from '../api/client';
import type {
  AnalysisStatus,
  ApiErrorDetail,
  ContainmentControl,
  Incident,
  NetworkEvidence,
  ServiceStatus,
  SimulationResult,
} from '../types/incident';

export type Screen = 'landing' | 'analyzing' | 'incident' | 'error';
export type Mode = 'replay' | 'investigate' | 'contain';
export type ViewMode = 'focused' | 'all';
export type Scenario = 'observed' | 'simulated';
export type Selection = { kind: 'asset' | 'event' | 'edge'; id: string } | null;
export const SPEEDS = [1, 2, 5, 10] as const;
export type Speed = (typeof SPEEDS)[number];

export interface AppError extends ApiErrorDetail {
  detail?: string | null;
}

const MAX_EVIDENCE_CACHE = 2000;

interface State {
  screen: Screen;
  service: ServiceStatus | null;
  analysis: AnalysisStatus | null;
  incident: Incident | null;
  error: AppError | null;
  mode: Mode;
  selection: Selection;
  viewMode: ViewMode;
  scenario: Scenario;
  t: number;
  playing: boolean;
  speed: Speed;
  simulation: SimulationResult | null;
  simulating: boolean;
  simulationError: string | null;
  evidence: Record<string, NetworkEvidence>;
  evidenceLoading: boolean;
  stopWatch: (() => void) | null;

  loadService: () => Promise<void>;
  startDemo: () => Promise<void>;
  upload: (file: File) => Promise<void>;
  onStatus: (status: AnalysisStatus) => void;
  fail: (err: AppError) => void;
  reset: () => void;
  setMode: (mode: Mode) => void;
  select: (selection: Selection) => void;
  setViewMode: (v: ViewMode) => void;
  setScenario: (s: Scenario) => void;
  setT: (t: number) => void;
  setPlaying: (p: boolean) => void;
  setSpeed: (s: Speed) => void;
  runSimulation: (controls: ContainmentControl[]) => Promise<void>;
  clearSimulation: () => void;
  loadEvidence: (ids: string[]) => Promise<void>;
}

const toAppError = (e: unknown): AppError => {
  if (e instanceof ApiError) return { ...e.detail };
  return { code: 'UNEXPECTED', title: 'SOMETHING WENT WRONG', message: e instanceof Error ? e.message : String(e) };
};

export const useApp = create<State>((set, get) => ({
  screen: 'landing',
  service: null,
  analysis: null,
  incident: null,
  error: null,
  mode: 'replay',
  selection: null,
  viewMode: 'focused',
  scenario: 'observed',
  t: 0,
  playing: false,
  speed: 5,
  simulation: null,
  simulating: false,
  simulationError: null,
  evidence: {},
  evidenceLoading: false,
  stopWatch: null,

  loadService: async () => {
    try {
      set({ service: await api.status() });
    } catch {
      set({ service: null });
    }
  },

  startDemo: async () => {
    get().stopWatch?.();
    set({ screen: 'analyzing', analysis: null, error: null, incident: null, simulation: null });
    try {
      const status = await api.startDemo();
      get().onStatus(status);
      if (status.state !== 'COMPLETE' && status.state !== 'FAILED') {
        set({ stopWatch: watchAnalysis(status.incident_id, get().onStatus, (e) => get().fail(e.detail)) });
      }
    } catch (e) {
      get().fail(toAppError(e));
    }
  },

  upload: async (file: File) => {
    get().stopWatch?.();
    set({
      screen: 'analyzing',
      error: null,
      incident: null,
      simulation: null,
      analysis: {
        incident_id: '',
        state: 'UPLOADING',
        steps: [],
        demo: false,
        showcase: false,
        filename: file.name,
        error_code: null,
        error_title: null,
        error_message: null,
        error_detail: null,
        created_at: Date.now() / 1000,
        updated_at: Date.now() / 1000,
        stats: {},
      },
    });
    try {
      const status = await api.upload(file);
      get().onStatus(status);
      set({ stopWatch: watchAnalysis(status.incident_id, get().onStatus, (e) => get().fail(e.detail)) });
    } catch (e) {
      get().fail(toAppError(e));
    }
  },

  onStatus: (status: AnalysisStatus) => {
    set({ analysis: status });
    if (status.state === 'FAILED') {
      get().fail({
        code: status.error_code ?? 'FAILED',
        title: status.error_title ?? 'ANALYSIS FAILED',
        message: status.error_message ?? 'The analysis did not complete.',
        detail: status.error_detail,
      });
    } else if (status.state === 'COMPLETE' && !get().incident) {
      api
        .incident(status.incident_id)
        .then(({ incident }) => {
          set({ incident, t: 0, playing: false, scenario: 'observed', simulation: null, selection: null, mode: 'replay', evidence: {} });
        })
        .catch((e) => get().fail(toAppError(e)));
    }
  },

  fail: (err: AppError) => {
    get().stopWatch?.();
    set({ screen: 'error', error: err, stopWatch: null, playing: false });
  },

  reset: () => {
    get().stopWatch?.();
    set({
      screen: 'landing',
      analysis: null,
      incident: null,
      error: null,
      simulation: null,
      selection: null,
      mode: 'replay',
      scenario: 'observed',
      t: 0,
      playing: false,
      evidence: {},
      stopWatch: null,
    });
  },

  setMode: (mode) => set({ mode }),
  select: (selection) => set(selection ? { selection, mode: 'investigate' } : { selection }),
  setViewMode: (viewMode) => set({ viewMode }),
  setScenario: (scenario) => set({ scenario, t: 0, playing: true }),
  setT: (t) => set({ t }),
  setPlaying: (playing) => set({ playing }),
  setSpeed: (speed) => set({ speed }),

  runSimulation: async (controls) => {
    const incident = get().incident;
    if (!incident) return;
    set({ simulating: true, simulationError: null });
    try {
      const result = await api.simulate(incident.id, controls);
      set({ simulation: result, scenario: 'simulated', t: 0, playing: true, simulating: false });
    } catch (e) {
      set({ simulating: false, simulationError: toAppError(e).message });
    }
  },

  clearSimulation: () => set({ simulation: null, scenario: 'observed', simulationError: null, t: 0, playing: false }),

  loadEvidence: async (ids) => {
    const incident = get().incident;
    const missing = ids.filter((id) => !get().evidence[id]);
    if (!incident || missing.length === 0) return;
    set({ evidenceLoading: true });
    try {
      const { items } = await api.evidence(incident.id, missing);
      const merged = { ...get().evidence };
      for (const item of items) merged[item.id] = item;
      const keys = Object.keys(merged);
      if (keys.length > MAX_EVIDENCE_CACHE) for (const k of keys.slice(0, keys.length - MAX_EVIDENCE_CACHE)) delete merged[k];
      set({ evidence: merged, evidenceLoading: false });
    } catch {
      set({ evidenceLoading: false });
    }
  },
}));

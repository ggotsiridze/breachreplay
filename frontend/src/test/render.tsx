import { act } from '@testing-library/react';

import { useApp } from '../stores/appStore';
import type { Incident, SimulationResult } from '../types/incident';

const initial = useApp.getState();

export function resetStore() {
  act(() => {
    useApp.setState({ ...initial }, true);
  });
}

export function loadIncident(incident: Incident, extra: Partial<ReturnType<typeof useApp.getState>> = {}) {
  act(() => {
    useApp.setState({ screen: 'incident', incident, t: 0, playing: false, mode: 'replay', scenario: 'observed', simulation: null as SimulationResult | null, ...extra });
  });
}

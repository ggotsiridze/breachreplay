import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { api } from '../api/client';
import { buildTimeline } from '../replay/engine';
import { useApp } from '../stores/appStore';
import { evidence, incident, simulation } from '../test/fixtures';
import { loadIncident, resetStore } from '../test/render';
import { IncidentView } from './IncidentView';

const timeline = buildTimeline(incident);
const at = (type: string) => timeline.events.find((e) => e.event.event_type === type)!.at;

function renderView() {
  return render(<IncidentView incident={useApp.getState().incident!} />);
}

describe('IncidentView', () => {
  beforeEach(() => {
    resetStore();
    vi.restoreAllMocks();
    vi.spyOn(api, 'evidence').mockImplementation(async (_id, ids) => ({ total: ids.length, items: evidence.filter((e) => ids.includes(e.id)) }));
    loadIncident(incident);
  });

  it('renders the incident graph with custom asset nodes', () => {
    renderView();
    expect(screen.getByTestId('incident-graph')).toBeInTheDocument();
    for (const id of ['asset-web-01', 'asset-ws-03', 'asset-db-01', 'asset-203-0-113-45']) {
      expect(screen.getByTestId(`node-${id}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId('node-asset-db-01')).toHaveTextContent('Crown jewel');
    expect(screen.getByTestId('source-chip')).toHaveTextContent(/synthetic/i);
  });

  it('updates node state, phase and current event as time moves', async () => {
    renderView();
    expect(screen.getByTestId('node-asset-ws-03')).toHaveAttribute('data-state', 'NORMAL');
    act(() => useApp.getState().setT(at('lateral_movement') + 0.2));
    expect(screen.getByTestId('node-asset-ws-03')).toHaveAttribute('data-state', 'AFFECTED');
    expect(screen.getByTestId('phase-indicator')).toHaveTextContent('Lateral Movement');
    const current = screen.getByTestId('current-event');
    // the card cross-fades between events (AnimatePresence)
    await waitFor(() => expect(current).toHaveTextContent('Lateral movement'));
    expect(current).toHaveTextContent('T1021.002');
    expect(current).toHaveTextContent('HIGH CONFIDENCE');
  });

  it('seeks with the timeline scrubber and pauses playback', () => {
    act(() => useApp.setState({ playing: true }));
    renderView();
    fireEvent.change(screen.getByTestId('timeline-scrubber'), { target: { value: String(at('crown_jewel_access') + 0.5) } });
    expect(useApp.getState().playing).toBe(false);
    expect(screen.getByTestId('crown-status')).toHaveTextContent('YES');
    expect(screen.getByTestId('crown-moment')).toHaveTextContent('Crown jewel reached');
    fireEvent.change(screen.getByTestId('timeline-scrubber'), { target: { value: '1' } });
    expect(screen.getByTestId('crown-status')).toHaveTextContent('NO');
    expect(screen.getByTestId('node-asset-db-01')).toHaveAttribute('data-state', 'NORMAL');
  });

  it('changes replay speed and shows the speed badge', async () => {
    renderView();
    expect(screen.getByTestId('speed-badge')).toHaveTextContent('5x REPLAY');
    await userEvent.click(screen.getByRole('button', { name: '10x' }));
    expect(useApp.getState().speed).toBe(10);
    expect(screen.getByTestId('speed-badge')).toHaveTextContent('10x REPLAY');
  });

  it('play, pause, restart and step controls drive the replay state', async () => {
    renderView();
    await userEvent.click(screen.getByTestId('play-toggle'));
    expect(useApp.getState().playing).toBe(true);
    await userEvent.click(screen.getByTestId('play-toggle'));
    expect(useApp.getState().playing).toBe(false);
    await userEvent.click(screen.getByRole('button', { name: 'Next event' }));
    expect(useApp.getState().t).toBeCloseTo(timeline.events[0].at + 0.01, 3);
    await userEvent.click(screen.getByRole('button', { name: 'Jump to end' }));
    expect(useApp.getState().t).toBe(timeline.duration);
    await userEvent.click(screen.getByRole('button', { name: 'Restart replay' }));
    expect(useApp.getState().t).toBe(0);
    expect(useApp.getState().playing).toBe(true);
  });

  it('opens the investigate drawer with evidence and MITRE information', async () => {
    renderView();
    act(() => useApp.getState().select({ kind: 'asset', id: 'asset-ws-03' }));
    const drawer = await screen.findByTestId('investigate-drawer');
    expect(within(drawer).getByRole('heading', { name: 'WS-03' })).toBeInTheDocument();
    expect(within(drawer).getByText(/high-confidence affected/i)).toBeInTheDocument();
    expect(within(drawer).getByTestId('mitre-mapping')).toHaveTextContent('T1021.002');
    expect(within(drawer).getByTestId('reasons')).toHaveTextContent('Administrative share accessed');
    expect(await within(drawer).findByText(/NTLM authentication as CORP-DEMO\\svc-demo/)).toBeInTheDocument();
    expect(api.evidence).toHaveBeenCalled();
  });

  it('shows why an event is not mapped to ATT&CK', () => {
    renderView();
    act(() => useApp.getState().select({ kind: 'event', id: 'evt-01' }));
    expect(screen.getByTestId('mitre-unmapped')).toHaveTextContent(/Not mapped/);
  });

  it('selects controls and runs a containment simulation', async () => {
    const spy = vi.spyOn(api, 'simulate').mockResolvedValue(simulation);
    renderView();
    await userEvent.click(screen.getByTestId('stop-the-breach'));
    const panel = screen.getByTestId('contain-panel');
    const isolate = within(panel).getByTestId('control-isolate_asset');
    expect(within(isolate).getByRole('checkbox')).toBeChecked();
    expect(within(isolate).getByLabelText('Isolate asset target')).toHaveValue('asset-ws-03');
    await userEvent.click(within(panel).getByRole('checkbox', { name: 'Block destination port' }));
    await userEvent.click(within(panel).getByRole('checkbox', { name: 'Block destination port' }));
    await userEvent.click(within(panel).getByTestId('run-simulation'));
    expect(spy).toHaveBeenCalledWith(incident.id, [{ control_type: 'isolate_asset', activation: 'first_detection', asset_id: 'asset-ws-03' }]);
    expect(useApp.getState().scenario).toBe('simulated');
    const compare = await screen.findByTestId('comparison-panel');
    expect(within(compare).getByTestId('compare-crown-jewel-reached')).toHaveTextContent('NO');
    expect(within(compare).getByTestId('compare-observed-path')).toHaveTextContent('INTERRUPTED');
    expect(compare).toHaveTextContent('Breach interrupted');
    expect(compare).toHaveTextContent('SIMULATED CONTAINMENT models the observed incident graph only');
  });

  it('renders the simulated outcome on the graph', () => {
    loadIncident(incident, { simulation, scenario: 'simulated', t: buildTimeline(incident, simulation).duration });
    renderView();
    expect(screen.getByTestId('scenario-chip')).toHaveTextContent('Simulated outcome');
    expect(screen.getByTestId('node-asset-ws-03')).toHaveAttribute('data-state', 'CONTAINED');
    expect(screen.getByTestId('node-asset-db-01')).toHaveAttribute('data-state', 'PROTECTED');
    expect(screen.getByTestId('crown-status')).toHaveTextContent('PROTECTED');
  });

  it('clears the simulation and returns to the observed replay', async () => {
    loadIncident(incident, { simulation, scenario: 'simulated', mode: 'contain' });
    renderView();
    await userEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(useApp.getState().simulation).toBeNull();
    expect(useApp.getState().scenario).toBe('observed');
    expect(screen.getByTestId('scenario-chip')).toHaveTextContent('Observed evidence');
  });

  it('switches between focused path and all connections', async () => {
    renderView();
    expect(screen.queryByTestId('node-asset-dns-01')).not.toBeInTheDocument();
    await userEvent.click(screen.getByTestId('view-all'));
    expect(screen.getByTestId('node-asset-dns-01')).toBeInTheDocument();
  });

  it('explains when no incident path was found', () => {
    loadIncident({ ...incident, incident_found: false, events: [], primary_attack_path: [], primary_attack_edges: [] });
    renderView();
    expect(screen.getByTestId('no-incident')).toHaveTextContent('did not find enough correlated evidence');
    expect(screen.queryByTestId('stop-the-breach')).not.toBeInTheDocument();
  });
});

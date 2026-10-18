import { act, render, screen } from '@testing-library/react';

import { useApp } from '../stores/appStore';
import { incident } from '../test/fixtures';
import { resetStore } from '../test/render';
import type { AnalysisStatus, AnalysisStep } from '../types/incident';
import { AnalysisProgress } from './AnalysisProgress';

const labels = ['Capture received', 'File validated', 'Zeek analysis', 'Suricata analysis', 'Normalizing evidence', 'Correlating incident', 'Building attack graph'];

function status(done: number, state: AnalysisStatus['state'], showcase = false): AnalysisStatus {
  const steps: AnalysisStep[] = labels.map((label, i) => ({
    state: 'UPLOADING',
    label,
    status: i < done ? (showcase && i > 0 ? 'skipped' : 'done') : i === done ? 'running' : 'pending',
    detail: i < done ? `detail ${i}` : null,
    started_at: null,
    finished_at: null,
  }));
  return {
    incident_id: 'x'.repeat(32),
    state,
    steps,
    demo: true,
    showcase,
    filename: 'breachreplay-demo.pcap',
    error_code: null,
    error_title: null,
    error_message: null,
    error_detail: null,
    created_at: 0,
    updated_at: 0,
    stats: {},
  };
}

// Each revealed step schedules the next reveal from an effect, so advance in steps.
function advance(ms: number) {
  for (let elapsed = 0; elapsed < ms; elapsed += 100) act(() => vi.advanceTimersByTime(100));
}

describe('AnalysisProgress', () => {
  beforeEach(() => {
    resetStore();
    vi.useFakeTimers();
  });
  afterEach(() => vi.useRealTimers());

  it('reveals pipeline steps in order and marks the running one', () => {
    act(() => useApp.setState({ screen: 'analyzing', analysis: status(3, 'RUNNING_SURICATA') }));
    render(<AnalysisProgress />);
    expect(screen.getByText('Analyzing network evidence')).toBeInTheDocument();
    expect(screen.getByText('Demo incident · synthetic network traffic')).toBeInTheDocument();
    expect(screen.getByTestId('step-0')).toHaveAttribute('data-status', 'running');
    advance(2000);
    expect(screen.getByTestId('step-0')).toHaveAttribute('data-status', 'done');
    expect(screen.getByTestId('step-2')).toHaveAttribute('data-status', 'done');
    expect(screen.getByTestId('step-3')).toHaveAttribute('data-status', 'running');
    expect(screen.getByTestId('step-6')).toHaveAttribute('data-status', 'pending');
  });

  it('transitions to the incident once complete', () => {
    act(() => useApp.setState({ screen: 'analyzing', analysis: status(7, 'COMPLETE'), incident }));
    render(<AnalysisProgress />);
    advance(5000);
    expect(useApp.getState().screen).toBe('incident');
    expect(useApp.getState().playing).toBe(true);
  });

  it('labels showcase mode as precomputed', () => {
    act(() => useApp.setState({ screen: 'analyzing', analysis: status(7, 'COMPLETE', true) }));
    render(<AnalysisProgress />);
    expect(screen.getByText('Loading showcase incident')).toBeInTheDocument();
    advance(3000);
    expect(screen.getAllByText('precomputed').length).toBeGreaterThan(0);
  });
});

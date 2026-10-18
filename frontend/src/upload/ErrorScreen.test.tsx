import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { useApp } from '../stores/appStore';
import { resetStore } from '../test/render';
import { ErrorScreen } from './ErrorScreen';

describe('ErrorScreen', () => {
  beforeEach(resetStore);

  it('shows a professional failure with technical details on demand', async () => {
    act(() =>
      useApp.setState({
        screen: 'error',
        error: { code: 'ANALYZER_FAILED', title: 'ANALYSIS FAILED', message: 'Zeek exited unexpectedly (exit code 1).', detail: 'fatal error in capture.pcap' },
      }),
    );
    render(<ErrorScreen />);
    expect(screen.getByRole('heading', { name: 'ANALYSIS FAILED' })).toBeInTheDocument();
    expect(screen.getByText('Zeek exited unexpectedly (exit code 1).')).toBeInTheDocument();
    expect(screen.queryByTestId('error-detail')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /view technical details/i }));
    expect(screen.getByTestId('error-detail')).toHaveTextContent('ANALYZER_FAILED');
    expect(screen.getByTestId('error-detail')).toHaveTextContent('fatal error');
  });

  it('shows the unsupported capture message', () => {
    act(() =>
      useApp.setState({ screen: 'error', error: { code: 'UNSUPPORTED_CAPTURE', title: 'UNSUPPORTED CAPTURE', message: 'No compatible Ethernet/IP traffic could be analyzed.' } }),
    );
    render(<ErrorScreen />);
    expect(screen.getByText('UNSUPPORTED CAPTURE')).toBeInTheDocument();
  });

  it('returns to the landing page', async () => {
    act(() => useApp.setState({ screen: 'error', error: { code: 'X', title: 'T', message: 'M' } }));
    render(<ErrorScreen />);
    await userEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(useApp.getState().screen).toBe('landing');
  });
});

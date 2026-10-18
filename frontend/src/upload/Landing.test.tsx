import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { api } from '../api/client';
import { useApp } from '../stores/appStore';
import { resetStore } from '../test/render';
import { Landing } from './Landing';

describe('Landing', () => {
  beforeEach(() => {
    resetStore();
    vi.restoreAllMocks();
  });

  it('shows the branding, tagline and product pillars', () => {
    render(<Landing />);
    expect(screen.getByRole('heading', { name: 'BREACHREPLAY' })).toBeInTheDocument();
    expect(screen.getByText('Turn network evidence into an attack you can watch.')).toBeInTheDocument();
    expect(screen.getByText('Replay')).toBeInTheDocument();
    expect(screen.getByText('Investigate')).toBeInTheDocument();
    expect(screen.getByText('Contain')).toBeInTheDocument();
    expect(screen.getByText(/drop pcap here/i)).toBeInTheDocument();
  });

  it('starts the demo analysis', async () => {
    const spy = vi.spyOn(api, 'startDemo').mockResolvedValue({
      incident_id: 'a'.repeat(32),
      state: 'RUNNING_ZEEK',
      steps: [],
      demo: true,
      showcase: false,
      filename: 'breachreplay-demo.pcap',
      error_code: null,
      error_title: null,
      error_message: null,
      error_detail: null,
      created_at: 0,
      updated_at: 0,
      stats: {},
    });
    vi.spyOn(api, 'analysisStatus').mockResolvedValue({} as never);
    render(<Landing />);
    await userEvent.click(screen.getByTestId('watch-demo'));
    expect(spy).toHaveBeenCalledOnce();
    expect(useApp.getState().screen).toBe('analyzing');
    useApp.getState().stopWatch?.();
  });

  it('rejects files that are not captures before uploading', () => {
    const upload = vi.spyOn(api, 'upload');
    render(<Landing />);
    const input = screen.getByTestId('file-input');
    fireEvent.change(input, { target: { files: [new File(['hello'], 'notes.txt', { type: 'text/plain' })] } });
    expect(screen.getByRole('alert')).toHaveTextContent('Only .pcap and .pcapng');
    expect(upload).not.toHaveBeenCalled();
  });

  it('uploads a capture and switches to the analysis view', async () => {
    const upload = vi.spyOn(api, 'upload').mockReturnValue(new Promise(() => {}));
    render(<Landing />);
    fireEvent.change(screen.getByTestId('file-input'), { target: { files: [new File([new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1])], 'case.pcap')] } });
    expect(upload).toHaveBeenCalledOnce();
    expect(useApp.getState().screen).toBe('analyzing');
    expect(useApp.getState().analysis?.filename).toBe('case.pcap');
  });

  it('disables uploads in showcase mode', () => {
    useApp.setState({ service: { service: 'breachreplay', showcase_mode: true, public_mode: true, uploads_enabled: false, max_upload_mb: 50, analyzers: {} } });
    render(<Landing />);
    expect(screen.getByText('Uploads disabled in showcase demo')).toBeInTheDocument();
    expect(screen.getByTestId('dropzone')).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByText(/precomputed synthetic incident/i)).toBeInTheDocument();
  });
});

import type {
  AnalysisStatus,
  ApiErrorDetail,
  ContainmentControl,
  Incident,
  NetworkEvidence,
  ServiceStatus,
  SimulationResult,
} from '../types/incident';

export class ApiError extends Error {
  readonly status: number;
  readonly detail: ApiErrorDetail;

  constructor(status: number, detail: ApiErrorDetail) {
    super(detail.message);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, { ...init, headers: { Accept: 'application/json', ...(init?.headers ?? {}) } });
  } catch {
    throw new ApiError(0, {
      code: 'NETWORK_ERROR',
      title: 'BACKEND UNREACHABLE',
      message: 'The BreachReplay API could not be reached. Is the backend running?',
    });
  }
  const text = await response.text();
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  if (!response.ok) {
    const detail = (body as { detail?: ApiErrorDetail } | undefined)?.detail;
    throw new ApiError(response.status, {
      code: detail?.code ?? `HTTP_${response.status}`,
      title: detail?.title ?? 'REQUEST FAILED',
      message: detail?.message ?? `The API returned HTTP ${response.status}.`,
    });
  }
  return body as T;
}

export const api = {
  status: () => request<ServiceStatus>('/api/status'),
  startDemo: () => request<AnalysisStatus>('/api/incidents/demo', { method: 'POST' }),
  upload: (file: File) => {
    const form = new FormData();
    form.append('file', file, file.name);
    return request<AnalysisStatus>('/api/incidents/upload', { method: 'POST', body: form });
  },
  analysisStatus: (id: string) => request<AnalysisStatus>(`/api/incidents/${encodeURIComponent(id)}/status`),
  incident: (id: string) => request<{ status: AnalysisStatus; incident: Incident }>(`/api/incidents/${encodeURIComponent(id)}`),
  evidence: (id: string, ids: string[]) =>
    request<{ total: number; items: NetworkEvidence[] }>(
      `/api/incidents/${encodeURIComponent(id)}/evidence?ids=${encodeURIComponent(ids.slice(0, 200).join(','))}&limit=200`,
    ),
  simulate: (id: string, controls: ContainmentControl[]) =>
    request<SimulationResult>(`/api/incidents/${encodeURIComponent(id)}/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ controls }),
    }),
};

/**
 * Follow analysis progress over the WebSocket, falling back to polling if the
 * socket cannot be opened. Returns an unsubscribe function.
 */
export function watchAnalysis(id: string, onStatus: (status: AnalysisStatus) => void, onError: (err: ApiError) => void): () => void {
  let closed = false;
  let pollTimer: ReturnType<typeof setTimeout> | undefined;
  let socket: WebSocket | undefined;

  const terminal = (s: AnalysisStatus) => s.state === 'COMPLETE' || s.state === 'FAILED';

  let polling = false;
  const startPolling = () => {
    if (polling || closed) return;
    polling = true;
    void poll();
  };

  const poll = async () => {
    if (closed) return;
    try {
      const s = await api.analysisStatus(id);
      onStatus(s);
      if (!terminal(s)) pollTimer = setTimeout(poll, 400);
    } catch (e) {
      onError(e as ApiError);
    }
  };

  try {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${proto}://${window.location.host}/ws/incidents/${encodeURIComponent(id)}`);
    let gotTerminal = false;
    socket.onmessage = (msg) => {
      const data = JSON.parse(msg.data as string) as { type: string; status?: AnalysisStatus };
      if (data.type === 'status' && data.status) {
        onStatus(data.status);
        if (terminal(data.status)) gotTerminal = true;
      }
    };
    socket.onerror = () => {
      if (!gotTerminal) startPolling();
    };
    socket.onclose = () => {
      if (!gotTerminal) startPolling();
    };
  } catch {
    startPolling();
  }

  return () => {
    closed = true;
    if (pollTimer) clearTimeout(pollTimer);
    socket?.close();
  };
}

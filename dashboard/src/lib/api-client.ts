import type {
  LiveBlastRadiusResponse,
  TyposquattingFindingDetailResponse,
  TyposquattingFindingListResponse,
  TyposquattingReviewResponse,
} from './api-types';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export async function fetchLiveBlastRadius(
  incidentId: number,
  options?: {
    maxDepth?: number;
    maxServices?: number;
    highConfidenceThreshold?: number;
    signal?: AbortSignal;
  }
): Promise<LiveBlastRadiusResponse> {
  const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
  const url = new URL(`${API_BASE_URL}/incidents/${incidentId}/blast-radius`, window.location.origin);

  if (options?.maxDepth !== undefined) {
    url.searchParams.set('maxDepth', options.maxDepth.toString());
  }
  if (options?.maxServices !== undefined) {
    url.searchParams.set('maxServices', options.maxServices.toString());
  }
  if (options?.highConfidenceThreshold !== undefined) {
    url.searchParams.set('highConfidenceThreshold', options.highConfidenceThreshold.toString());
  }

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
    signal: options?.signal,
  });

  if (!response.ok) {
    let code = 'UNKNOWN_ERROR';
    let message = response.statusText;

    try {
      const errorBody = await response.json();
      if (errorBody && typeof errorBody === 'object') {
        if ('code' in errorBody && typeof errorBody.code === 'string') code = errorBody.code;
        if ('message' in errorBody && typeof errorBody.message === 'string') message = errorBody.message;
      }
    } catch {
      // Ignore JSON parse errors for error responses
    }

    throw new ApiError(response.status, code, message);
  }

  return response.json() as Promise<LiveBlastRadiusResponse>;
}


function apiUrl(path: string): URL {
  const base = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
  return new URL(`${base}${path}`, window.location.origin);
}

async function readApiResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let code = 'UNKNOWN_ERROR';
    let message = response.statusText;
    try {
      const body = await response.json() as unknown;
      if (body && typeof body === 'object') {
        if ('code' in body && typeof body.code === 'string') code = body.code;
        if ('message' in body && typeof body.message === 'string') message = body.message;
      }
    } catch {
      // Keep the status text when an error body is not JSON.
    }
    throw new ApiError(response.status, code, message);
  }
  return response.json() as Promise<T>;
}

export async function fetchTyposquattingFindings(
  signal?: AbortSignal
): Promise<TyposquattingFindingListResponse> {
  const url = apiUrl('/typosquatting/findings');
  url.searchParams.set('limit', '200');
  return readApiResponse<TyposquattingFindingListResponse>(await fetch(url, {
    headers: { Accept: 'application/json' },
    signal,
  }));
}

export async function fetchTyposquattingFinding(
  findingId: number,
  signal?: AbortSignal
): Promise<TyposquattingFindingDetailResponse> {
  return readApiResponse<TyposquattingFindingDetailResponse>(await fetch(
    apiUrl(`/typosquatting/findings/${findingId}`),
    { headers: { Accept: 'application/json' }, signal }
  ));
}

export async function reviewTyposquattingFinding(
  findingId: number,
  action: 'dismiss' | 'promote',
  input: { readonly reason: string },
  idempotencyKey: string
): Promise<TyposquattingReviewResponse> {
  const token = import.meta.env.VITE_TYPOSQUATTING_ANALYST_TOKEN as string | undefined;
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'Idempotency-Key': idempotencyKey,
  };
  if (token?.trim()) headers.Authorization = `Bearer ${token.trim()}`;

  return readApiResponse<TyposquattingReviewResponse>(await fetch(
    apiUrl(`/typosquatting/findings/${findingId}/${action}`),
    {
      method: 'POST',
      headers,
      body: JSON.stringify(input),
    }
  ));
}

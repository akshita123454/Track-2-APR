import type { LiveBlastRadiusResponse } from './api-types';

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

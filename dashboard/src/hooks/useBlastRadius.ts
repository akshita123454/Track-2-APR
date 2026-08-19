import { useState, useEffect, useCallback, useRef } from 'react';
import type { LiveBlastRadiusResponse } from '../lib/api-types';
import { fetchLiveBlastRadius, ApiError } from '../lib/api-client';

export function useBlastRadius(incidentId: number | null) {
  const [data, setData] = useState<LiveBlastRadiusResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  
  const abortControllerRef = useRef<AbortController | null>(null);

  const fetchBlastRadius = useCallback(async (id: number) => {
    // Abort previous request if in flight
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const response = await fetchLiveBlastRadius(id, {
        signal: abortController.signal,
        // Optional default limits could be passed here
      });
      
      if (!abortController.signal.aborted) {
        setData(response);
        setError(null);
      }
    } catch (err) {
      if (!abortController.signal.aborted) {
        if (err instanceof ApiError) {
          if (err.status === 404) {
            setError(`Incident ${id} not found`);
          } else {
            setError(`Error: ${err.message} (${err.code})`);
          }
        } else if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('An unknown error occurred');
        }
      }
    } finally {
      if (!abortController.signal.aborted) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    if (incidentId === null) {
      setData(null);
      setError(null);
      setLoading(false);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      return;
    }

    fetchBlastRadius(incidentId);

    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [incidentId, fetchBlastRadius]);

  const refetch = useCallback(() => {
    if (incidentId !== null) {
      fetchBlastRadius(incidentId);
    }
  }, [incidentId, fetchBlastRadius]);

  return { data, loading, error, refetch };
}

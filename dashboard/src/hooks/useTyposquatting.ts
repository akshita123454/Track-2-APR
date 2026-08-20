import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  TyposquattingFindingDetailResponse,
  TyposquattingFindingListResponse,
} from '../lib/api-types';
import {
  ApiError,
  fetchTyposquattingFinding,
  fetchTyposquattingFindings,
  reviewTyposquattingFinding,
} from '../lib/api-client';

function message(error: unknown): string {
  if (error instanceof ApiError) return `${error.message} (${error.code})`;
  return error instanceof Error ? error.message : 'The request could not be completed.';
}

export function useTyposquatting(findingId: number | null) {
  const [list, setList] = useState<TyposquattingFindingListResponse | null>(null);
  const [detail, setDetail] = useState<TyposquattingFindingDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reviewAttempt = useRef<{
    readonly signature: string;
    readonly idempotencyKey: string;
  } | null>(null);

  const loadList = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);
    try {
      setList(await fetchTyposquattingFindings(signal));
    } catch (cause) {
      if (!signal?.aborted) setError(message(cause));
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void loadList(controller.signal);
    return () => controller.abort();
  }, [loadList]);

  useEffect(() => {
    if (findingId === null) {
      setDetail(null);
      return;
    }
    const controller = new AbortController();
    setDetailLoading(true);
    setError(null);
    void fetchTyposquattingFinding(findingId, controller.signal)
      .then(setDetail)
      .catch((cause) => {
        if (!controller.signal.aborted) setError(message(cause));
      })
      .finally(() => {
        if (!controller.signal.aborted) setDetailLoading(false);
      });
    return () => controller.abort();
  }, [findingId]);

  const review = useCallback(async (
    action: 'dismiss' | 'promote',
    input: { readonly reason: string }
  ) => {
    if (findingId === null) return;
    const signature = JSON.stringify([findingId, action, input.reason]);
    if (reviewAttempt.current?.signature !== signature) {
      reviewAttempt.current = {
        signature,
        idempotencyKey: `dashboard-${action}-${findingId}-${crypto.randomUUID()}`,
      };
    }
    const attempt = reviewAttempt.current!;

    setActionLoading(true);
    setError(null);
    try {
      await reviewTyposquattingFinding(
        findingId,
        action,
        input,
        attempt.idempotencyKey
      );
      if (reviewAttempt.current === attempt) reviewAttempt.current = null;
      const [nextList, nextDetail] = await Promise.all([
        fetchTyposquattingFindings(),
        fetchTyposquattingFinding(findingId),
      ]);
      setList(nextList);
      setDetail(nextDetail);
    } catch (cause) {
      setError(message(cause));
    } finally {
      setActionLoading(false);
    }
  }, [findingId]);

  return {
    list,
    detail,
    loading,
    detailLoading,
    actionLoading,
    error,
    refetch: () => loadList(),
    review,
  };
}

import { useMemo } from "react";
import { useDashboardSummary } from "./queries/useDashboardQueries";

export function useDashboard(intervalMs = 15000) {
  const query = useDashboardSummary({
    refetchInterval: intervalMs,
  });

  return useMemo(() => ({
    data: query.data || null,
    loading: query.isLoading,
    error: query.error?.message || null,
    updatedAt: query.dataUpdatedAt ? new Date(query.dataUpdatedAt) : null,
    refresh: query.refetch,
    isFetching: query.isFetching,
  }), [query.data, query.isLoading, query.error, query.dataUpdatedAt, query.refetch, query.isFetching]);
}

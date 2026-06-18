import { useMemo } from "react";
import { incidentListFrom, useIncidentsQuery } from "./queries/useIncidentQueries";

export function useIncidents(filters = {}) {
  const query = useIncidentsQuery(filters);
  const data = query.data || {};
  const items = incidentListFrom(data);

  return useMemo(() => ({
    items,
    incidents: items,
    total: data.count ?? data.total ?? items.length,
    page: data.page ?? 1,
    pages: data.pages ?? 1,
    loading: query.isLoading,
    error: query.error?.message || data.error || null,
    refetch: query.refetch,
    isFetching: query.isFetching,
  }), [items, data, query.isLoading, query.error, query.refetch, query.isFetching]);
}

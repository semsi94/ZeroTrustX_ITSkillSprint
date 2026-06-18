import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import { getDashboardSummary } from "../../services/dashboard.service";

export function useDashboardSummary(options = {}) {
  return useQuery({
    queryKey: queryKeys.dashboard.summary,
    queryFn: getDashboardSummary,
    staleTime: 30_000,
    ...options,
  });
}

export function useSystemStatus(options = {}) {
  return useDashboardSummary(options);
}

export function useCiaRisk(options = {}) {
  return useDashboardSummary({
    select: (data) => data?.cia_scores || {},
    ...options,
  });
}

export function useRecentIncidents(options = {}) {
  return useDashboardSummary({
    select: (data) => data?.recent_incidents || [],
    ...options,
  });
}

export function useRecentAlerts(options = {}) {
  return useDashboardSummary({
    select: (data) => data?.recent_alerts || [],
    ...options,
  });
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import {
  getLogChain,
  getSavedSearches,
  getSplunkAlerts,
  getSplunkReports,
  runSearchFromSaved,
  runSplunkSearch,
  syncSplunkCache,
} from "../../services/splunk.service";

export function useSplunkAlerts(options = {}) {
  return useQuery({
    queryKey: queryKeys.splunk.alerts,
    queryFn: getSplunkAlerts,
    staleTime: 60_000,
    ...options,
  });
}

export function useSplunkReports(options = {}) {
  return useQuery({
    queryKey: queryKeys.splunk.reports,
    queryFn: getSplunkReports,
    staleTime: 60_000,
    ...options,
  });
}

export function useSplunkSavedSearches(options = {}) {
  return useQuery({
    queryKey: queryKeys.splunk.savedSearches,
    queryFn: getSavedSearches,
    staleTime: 60_000,
    ...options,
  });
}

export function useRunInvestigationSearch() {
  return useMutation({
    mutationFn: runSplunkSearch,
  });
}

export function useRunSavedSearches() {
  return useMutation({
    mutationFn: runSearchFromSaved,
  });
}

export function useLogChainMutation() {
  return useMutation({
    mutationFn: getLogChain,
  });
}

export function useSyncSplunkCache() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: syncSplunkCache,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["splunk"] });
    },
  });
}

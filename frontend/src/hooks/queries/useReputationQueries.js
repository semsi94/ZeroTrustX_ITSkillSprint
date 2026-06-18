import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import {
  enrichIps,
  enrichIpsFromEvents,
  getIncidentIpReputation,
  getIpReputation,
  getRecentIpReputation,
  getReputationObservations,
  getReputationProviderStatus,
  getReputationQueueStatus,
  refreshIpReputation,
  saveReputationSettings,
  syncRecentIps,
  testAbuseIpdb,
  testVirusTotal,
} from "../../services/reputation.service";

export function useIpReputation(ip, options = {}) {
  return useQuery({
    queryKey: queryKeys.reputation.ip(ip),
    queryFn: () => getIpReputation(ip),
    enabled: Boolean(ip),
    staleTime: 5 * 60 * 1000,
    ...options,
  });
}

export function useIncidentIpReputation(incidentId, options = {}) {
  return useQuery({
    queryKey: queryKeys.reputation.incident(incidentId),
    queryFn: () => getIncidentIpReputation(incidentId),
    enabled: Boolean(incidentId),
    staleTime: 30_000,
    refetchInterval: (query) => {
      const items = query.state.data?.reputations || [];
      return items.some((item) => !item.last_checked_at) ? 10_000 : false;
    },
    ...options,
  });
}

export function useReputationObservations(ip, options = {}) {
  return useQuery({
    queryKey: queryKeys.reputation.observations(ip),
    queryFn: () => getReputationObservations(ip),
    enabled: Boolean(ip),
    staleTime: 60_000,
    ...options,
  });
}

export function useRecentIpReputation(options = {}) {
  return useQuery({ queryKey: queryKeys.reputation.recent, queryFn: getRecentIpReputation, staleTime: 60_000, ...options });
}

export function useReputationQueueStatus(options = {}) {
  return useQuery({ queryKey: queryKeys.reputation.queueStatus, queryFn: getReputationQueueStatus, staleTime: 30_000, ...options });
}

export function useReputationProviderStatus(options = {}) {
  return useQuery({ queryKey: queryKeys.reputation.providerStatus, queryFn: getReputationProviderStatus, staleTime: 30_000, ...options });
}

export function useEnrichIpsFromEvents() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: enrichIpsFromEvents,
    onSuccess: (_data, variables) => {
      if (variables?.incident_id) qc.invalidateQueries({ queryKey: queryKeys.reputation.incident(variables.incident_id) });
      qc.invalidateQueries({ queryKey: queryKeys.reputation.recent });
    },
  });
}

export function useEnrichIps() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: enrichIps,
    onSuccess: (_data, variables) => {
      (variables?.ips || []).forEach((ip) => qc.invalidateQueries({ queryKey: queryKeys.reputation.ip(ip) }));
      qc.invalidateQueries({ queryKey: queryKeys.reputation.recent });
    },
  });
}

export function useRefreshIpReputation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ ip }) => refreshIpReputation(ip),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: queryKeys.reputation.ip(variables.ip) });
      qc.invalidateQueries({ queryKey: queryKeys.reputation.observations(variables.ip) });
      qc.invalidateQueries({ queryKey: ["reputation"] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: queryKeys.dashboard.summary });
    },
  });
}

export function useSyncRecentIps() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: syncRecentIps,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["reputation"] });
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

export function useSaveReputationSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: saveReputationSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.integrations.status(false) });
      qc.invalidateQueries({ queryKey: queryKeys.reputation.providerStatus });
    },
  });
}

export function useTestAbuseIpdb() {
  return useMutation({ mutationFn: testAbuseIpdb });
}

export function useTestVirusTotal() {
  return useMutation({ mutationFn: testVirusTotal });
}

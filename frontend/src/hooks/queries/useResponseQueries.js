import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import {
  blockIp,
  checkIp,
  getBlockedIps,
  getFirewallActions,
  getFirewallStatus,
  runFirewallAction,
  unblockIp,
} from "../../services/response.service";

export function useFirewallStatus(options = {}) {
  return useQuery({
    queryKey: queryKeys.response.firewallStatus,
    queryFn: getFirewallStatus,
    staleTime: 30_000,
    ...options,
  });
}

export function useContainmentHistory(options = {}) {
  return useQuery({
    queryKey: queryKeys.response.containmentHistory,
    queryFn: getFirewallActions,
    staleTime: 30_000,
    ...options,
  });
}

export function useBlockedIps(options = {}) {
  return useQuery({
    queryKey: queryKeys.response.blockedIps,
    queryFn: getBlockedIps,
    staleTime: 30_000,
    ...options,
  });
}

function invalidateFirewall(qc, incidentId) {
  qc.invalidateQueries({ queryKey: queryKeys.response.containmentHistory });
  qc.invalidateQueries({ queryKey: queryKeys.response.firewallStatus });
  qc.invalidateQueries({ queryKey: queryKeys.response.blockedIps });
  if (incidentId) qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(incidentId) });
}

export function useFirewallAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: runFirewallAction,
    onSuccess: (_data, variables) => {
      invalidateFirewall(qc, variables?.incident_id);
    },
  });
}

export function useBlockIp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: blockIp,
    onSuccess: (_data, variables) => invalidateFirewall(qc, variables?.incident_id),
  });
}

export function useUnblockIp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: unblockIp,
    onSuccess: (_data, variables) => invalidateFirewall(qc, variables?.incident_id),
  });
}

export function useCheckIp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: checkIp,
    onSuccess: (_data, variables) => invalidateFirewall(qc, variables?.incident_id),
  });
}

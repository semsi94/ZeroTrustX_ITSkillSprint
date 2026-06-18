import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import {
  disconnectSplunk,
  getIntegrationSchema,
  getIntegrationStatus,
  getSystemInfo,
  syncSplunkCache,
  updateIntegration,
} from "../../services/settings.service";

export function useIntegrationStatusQuery(refresh = false, options = {}) {
  return useQuery({
    queryKey: queryKeys.integrations.status(refresh),
    queryFn: () => getIntegrationStatus(refresh),
    staleTime: 30_000,
    ...options,
  });
}

export function useIntegrationSchema(options = {}) {
  return useQuery({
    queryKey: queryKeys.integrations.schema,
    queryFn: getIntegrationSchema,
    staleTime: 60_000,
    ...options,
  });
}

export function useSystemInfo(options = {}) {
  return useQuery({
    queryKey: queryKeys.integrations.systemInfo,
    queryFn: getSystemInfo,
    staleTime: 60_000,
    ...options,
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: updateIntegration,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }),
  });
}

export function useDisconnectSplunk() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: disconnectSplunk,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }),
  });
}

export function useSyncSplunkCache() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: syncSplunkCache,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["integrations"] });
      qc.invalidateQueries({ queryKey: ["splunk"] });
    },
  });
}

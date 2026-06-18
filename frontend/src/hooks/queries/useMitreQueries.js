import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import {
  analyzeIncidentMitre,
  createIncidentMitreLink,
  deleteIncidentMitreLink,
  downloadNavigatorLayer,
  getMitreHealth,
  getIncidentMitre,
  getMitreMatrix,
  syncMitreData,
  updateIncidentMitreLink,
} from "../../services/mitre.service";

export function useMitreMatrix(options = {}) {
  return useQuery({
    queryKey: queryKeys.mitre.matrix,
    queryFn: getMitreMatrix,
    staleTime: 60 * 60 * 1000,
    ...options,
  });
}

export function useMitreHealth(options = {}) {
  return useQuery({
    queryKey: queryKeys.mitre.health,
    queryFn: getMitreHealth,
    staleTime: 60 * 1000,
    ...options,
  });
}

export function useIncidentMitre(incidentId, options = {}) {
  return useQuery({
    queryKey: queryKeys.mitre.incident(incidentId),
    queryFn: () => getIncidentMitre(incidentId),
    enabled: Boolean(incidentId),
    staleTime: 30_000,
    ...options,
  });
}

export function useAnalyzeIncidentMitre() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: analyzeIncidentMitre,
    onSuccess: (_data, incidentId) => {
      qc.invalidateQueries({ queryKey: queryKeys.mitre.incident(incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(incidentId) });
    },
  });
}

export function useUpdateIncidentMitreLink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ incidentId, linkId, payload }) => updateIncidentMitreLink(incidentId, linkId, payload),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: queryKeys.mitre.incident(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(variables.incidentId) });
    },
  });
}

export function useCreateIncidentMitreLink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ incidentId, payload }) => createIncidentMitreLink(incidentId, payload),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: queryKeys.mitre.incident(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(variables.incidentId) });
    },
  });
}

export function useDeleteIncidentMitreLink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ incidentId, linkId }) => deleteIncidentMitreLink(incidentId, linkId),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: queryKeys.mitre.incident(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(variables.incidentId) });
    },
  });
}

export function useSyncMitreData() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: syncMitreData,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["mitre"] }),
  });
}

export function useExportNavigatorLayer() {
  return useMutation({
    mutationFn: downloadNavigatorLayer,
  });
}

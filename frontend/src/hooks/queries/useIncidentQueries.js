import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import {
  addEvidence,
  bulkAddEvidence,
  createIncident,
  deleteIncident,
  downloadIncidentPdf,
  addIncidentComment,
  getIncident,
  getIncidentActivity,
  getIncidentComments,
  getIncidentWorkflow,
  getIncidents,
  getTriggeredAlertDetail,
  syncSplunkAlertIncidents,
  updateIncident,
  updateIncidentWorkflow,
} from "../../services/incidents.service";

function incidentListFrom(data) {
  if (Array.isArray(data?.incidents)) return data.incidents;
  if (Array.isArray(data?.items)) return data.items;
  return [];
}

export function useIncidentsQuery(filters = {}, options = {}) {
  return useQuery({
    queryKey: queryKeys.incidents.list(filters),
    queryFn: () => getIncidents(filters),
    staleTime: 30_000,
    ...options,
  });
}

export function useIncident(id, options = {}) {
  return useQuery({
    queryKey: queryKeys.incidents.detail(id),
    queryFn: () => getIncident(id),
    enabled: Boolean(id),
    staleTime: 30_000,
    ...options,
  });
}

export function useTriggeredAlertDetail(id, options = {}) {
  return useQuery({
    queryKey: queryKeys.incidents.triggeredAlert(id),
    queryFn: () => getTriggeredAlertDetail(id),
    enabled: Boolean(id),
    staleTime: 30_000,
    ...options,
  });
}

export function useIncidentWorkflow(id, options = {}) {
  return useQuery({
    queryKey: queryKeys.incidents.workflow(id),
    queryFn: () => getIncidentWorkflow(id),
    enabled: Boolean(id),
    staleTime: 30_000,
    ...options,
  });
}

export function useIncidentComments(id, options = {}) {
  return useQuery({
    queryKey: queryKeys.incidents.comments(id),
    queryFn: () => getIncidentComments(id),
    enabled: Boolean(id),
    staleTime: 15_000,
    ...options,
  });
}

export function useIncidentActivity(id, options = {}) {
  return useQuery({
    queryKey: queryKeys.incidents.activity(id),
    queryFn: () => getIncidentActivity(id),
    enabled: Boolean(id),
    staleTime: 15_000,
    ...options,
  });
}

export function useCreateIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createIncident,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: queryKeys.dashboard.summary });
    },
  });
}

export function useUpdateIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }) => updateIncident(id, patch),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      if (variables?.id) qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(variables.id) });
      qc.invalidateQueries({ queryKey: queryKeys.dashboard.summary });
    },
  });
}

export function useUpdateIncidentWorkflow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }) => updateIncidentWorkflow(id, patch),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(variables.id) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.workflow(variables.id) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.activity(variables.id) });
      qc.invalidateQueries({ queryKey: ["incidents"] });
    },
  });
}

export function useAddIncidentComment() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body, comment_type = "internal_note" }) => addIncidentComment(id, { body, comment_type }),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(variables.id) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.comments(variables.id) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.activity(variables.id) });
    },
  });
}

export function useDeleteIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteIncident,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: queryKeys.dashboard.summary });
    },
  });
}

export function useAddEvidence() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ incidentId, event }) => addEvidence(incidentId, event),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.evidence(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.timeline(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.mitre.incident(variables.incidentId) });
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: queryKeys.dashboard.summary });
    },
  });
}

export function useBulkAddEvidence() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ incidentId, events }) => bulkAddEvidence(incidentId, events),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: queryKeys.incidents.detail(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.evidence(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.incidents.timeline(variables.incidentId) });
      qc.invalidateQueries({ queryKey: queryKeys.mitre.incident(variables.incidentId) });
      qc.invalidateQueries({ queryKey: ["incidents"] });
      qc.invalidateQueries({ queryKey: queryKeys.dashboard.summary });
    },
  });
}

export function useSyncSplunkAlertIncidents() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: syncSplunkAlertIncidents,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incidents"] }),
  });
}

export function useDownloadIncidentPdf() {
  return useMutation({
    mutationFn: downloadIncidentPdf,
  });
}

export { incidentListFrom };

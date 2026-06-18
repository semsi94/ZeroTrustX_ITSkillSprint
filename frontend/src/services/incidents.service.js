import { downloadBlob, request } from "../api/client";

function cleanParams(params = {}) {
  return Object.fromEntries(
    Object.entries(params).filter(([, value]) => value !== undefined && value !== null && value !== ""),
  );
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function normalizeIncidentPayload(payload) {
  const incident = payload?.incident ?? payload ?? null;
  if (!incident || typeof incident !== "object") {
    return { success: payload?.success ?? true, incident: null, error: payload?.error ?? null };
  }
  return {
    success: payload?.success ?? true,
    error: payload?.error ?? null,
    incident: {
      ...incident,
      evidence: asArray(incident.evidence),
      observables: asRecord(incident.observables),
      mitre_links: asArray(incident.mitre_links),
      comments: asArray(incident.comments),
      activity: asArray(incident.activity),
      containment_actions: asArray(incident.containment_actions ?? incident.response_actions),
      response_actions: asArray(incident.response_actions ?? incident.containment_actions),
      related_alerts: asArray(incident.related_alerts ?? incident.external_alerts),
      external_alerts: asArray(incident.external_alerts ?? incident.related_alerts),
      tickets: asArray(incident.tickets),
      workflow: asRecord(incident.workflow),
      entities: asRecord(incident.entities),
    },
  };
}

export function getIncidents(filters = {}) {
  return request(
    { method: "GET", url: "/api/incidents", params: cleanParams(filters) },
    "Failed to load incidents",
  );
}

export function getIncident(id) {
  return request({ method: "GET", url: `/api/incidents/${id}` }, "Failed to load incident").then(normalizeIncidentPayload);
}

export function createIncident(payload) {
  return request({ method: "POST", url: "/api/incidents", data: payload }, "Failed to create incident");
}

export function updateIncident(id, payload) {
  return request({ method: "PATCH", url: `/api/incidents/${id}`, data: payload }, "Failed to update incident");
}

export function deleteIncident(id) {
  return request({ method: "DELETE", url: `/api/incidents/${id}` }, "Failed to delete incident");
}

export function syncSplunkAlertIncidents() {
  return request({ method: "POST", url: "/api/incidents/sync-splunk-alerts" }, "Failed to sync Splunk alerts");
}

export function addEvidence(incidentId, event) {
  return request({ method: "POST", url: `/api/incidents/${incidentId}/evidence`, data: event }, "Failed to add evidence");
}

export function bulkAddEvidence(incidentId, events) {
  return request(
    { method: "POST", url: `/api/incidents/${incidentId}/evidence/bulk`, data: { events } },
    "Failed to add evidence",
  );
}

export function getTriggeredAlertDetail(id) {
  return request(
    { method: "GET", url: `/api/incidents/triggered-alerts/${id}` },
    "Failed to load triggered alert detail",
  );
}

export function getIncidentWorkflow(id) {
  return request({ method: "GET", url: `/api/incidents/${id}/workflow` }, "Failed to load incident workflow");
}

export function updateIncidentWorkflow(id, payload) {
  return request({ method: "PATCH", url: `/api/incidents/${id}/workflow`, data: payload }, "Failed to update incident workflow");
}

export function getIncidentComments(id) {
  return request({ method: "GET", url: `/api/incidents/${id}/comments` }, "Failed to load incident comments");
}

export function addIncidentComment(id, payload) {
  return request({ method: "POST", url: `/api/incidents/${id}/comments`, data: payload }, "Failed to add incident comment");
}

export function getIncidentActivity(id) {
  return request({ method: "GET", url: `/api/incidents/${id}/activity` }, "Failed to load incident activity");
}

export function downloadIncidentPdf(id) {
  return downloadBlob(
    { method: "GET", url: `/api/incidents/${id}/report/pdf` },
    "Failed to generate PDF report",
  );
}

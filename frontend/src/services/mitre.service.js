import { downloadBlob, request } from "../api/client";

export function getMitreMatrix() {
  return request({ method: "GET", url: "/api/mitre/matrix" }, "Failed to load MITRE matrix");
}

export function getMitreHealth() {
  return request({ method: "GET", url: "/api/mitre/health" }, "Failed to load MITRE data health");
}

export function syncMitreData() {
  return request({ method: "POST", url: "/api/mitre/sync" }, "Failed to sync MITRE ATT&CK data");
}

export function getIncidentMitre(incidentId) {
  return request({ method: "GET", url: `/api/incidents/${incidentId}/mitre` }, "Failed to load incident MITRE mapping");
}

export function analyzeIncidentMitre(incidentId) {
  return request({ method: "POST", url: `/api/incidents/${incidentId}/mitre/analyze` }, "Failed to analyze MITRE mapping");
}

export function createIncidentMitreLink(incidentId, payload) {
  return request(
    { method: "POST", url: `/api/incidents/${incidentId}/mitre-links`, data: payload },
    "Failed to add MITRE mapping",
  );
}

export function updateIncidentMitreLink(incidentId, linkId, payload) {
  return request(
    { method: "PATCH", url: `/api/incidents/${incidentId}/mitre-links/${linkId}`, data: payload },
    "Failed to update MITRE mapping",
  );
}

export function deleteIncidentMitreLink(incidentId, linkId) {
  return request(
    { method: "DELETE", url: `/api/incidents/${incidentId}/mitre-links/${linkId}` },
    "Failed to delete MITRE mapping",
  );
}

export function downloadNavigatorLayer(incidentId) {
  return downloadBlob(
    { method: "GET", url: `/api/incidents/${incidentId}/mitre/navigator-layer` },
    "Failed to export ATT&CK Navigator layer",
  );
}

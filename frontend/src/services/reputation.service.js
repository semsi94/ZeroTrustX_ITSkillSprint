import { request } from "../api/client";

export function getIpReputation(ip) {
  return request({ method: "GET", url: `/api/reputation/ip/${encodeURIComponent(ip)}` }, "Failed to load IP reputation");
}

export function refreshIpReputation(ip) {
  return request({ method: "POST", url: `/api/reputation/ip/${encodeURIComponent(ip)}/refresh` }, "Failed to refresh IP reputation");
}

export function enrichIps(payload) {
  return request({ method: "POST", url: "/api/reputation/enrich", data: payload }, "Failed to queue IP reputation enrichment");
}

export function enrichIpsFromEvents(payload) {
  return request({ method: "POST", url: "/api/reputation/enrich-from-events", data: payload }, "Failed to queue event IP reputation enrichment");
}

export function getReputationObservations(ip) {
  return request({ method: "GET", url: `/api/reputation/observations/${encodeURIComponent(ip)}` }, "Failed to load reputation observations");
}

export function getIncidentIpReputation(incidentId) {
  return request({ method: "GET", url: `/api/incidents/${incidentId}/ip-reputation` }, "Failed to load incident IP reputation");
}

export function getRecentIpReputation() {
  return request({ method: "GET", url: "/api/reputation/recent" }, "Failed to load recent IP reputation");
}

export function getReputationQueueStatus() {
  return request({ method: "GET", url: "/api/reputation/queue-status" }, "Failed to load reputation queue status");
}

export function getReputationProviderStatus() {
  return request({ method: "GET", url: "/api/reputation/provider-status" }, "Failed to load reputation provider status");
}

export function syncRecentIps() {
  return request({ method: "POST", url: "/api/reputation/sync-recent-ips" }, "Failed to sync recent IPs");
}

export function saveReputationSettings(payload) {
  return request({ method: "POST", url: "/api/reputation/settings", data: payload }, "Failed to save reputation settings");
}

export function testAbuseIpdb() {
  return request({ method: "POST", url: "/api/reputation/test/abuseipdb" }, "Failed to test AbuseIPDB");
}

export function testVirusTotal() {
  return request({ method: "POST", url: "/api/reputation/test/virustotal" }, "Failed to test VirusTotal");
}

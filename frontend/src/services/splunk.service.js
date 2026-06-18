import { request } from "../api/client";

export function getSavedSearches() {
  return request({ method: "GET", url: "/api/splunk/saved-searches" }, "Failed to load Splunk saved searches");
}

export function getSplunkAlerts() {
  return request({ method: "GET", url: "/api/splunk/alerts" }, "Failed to load Splunk alerts");
}

export function getSplunkReports() {
  return request({ method: "GET", url: "/api/splunk/reports" }, "Failed to load Splunk reports");
}

export function runSplunkSearch(payload) {
  return request({ method: "POST", url: "/api/splunk/search", data: payload }, "Splunk search failed");
}

export function runSearchFromSaved(payload) {
  return request(
    { method: "POST", url: "/api/splunk/search-from-saved", data: payload },
    "Saved search execution failed",
  );
}

export function getLogChain(payload) {
  return request({ method: "POST", url: "/api/splunk/log-chain", data: payload }, "Failed to load log chain");
}

export function syncSplunkCache(payload) {
  return request({ method: "POST", url: "/api/splunk/cache/sync", data: payload }, "Failed to sync Splunk cache");
}

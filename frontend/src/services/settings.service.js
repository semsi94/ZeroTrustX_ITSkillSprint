import { request } from "../api/client";

export function getIntegrationStatus(refresh = false) {
  return request(
    { method: "GET", url: "/settings/integration-status", params: refresh ? { refresh: true } : {} },
    "Failed to load integration status",
  );
}

export function getIntegrationSchema() {
  return request({ method: "GET", url: "/settings/integrations/schema" }, "Failed to load integration schema");
}

export function getSystemInfo() {
  return request({ method: "GET", url: "/settings/system-info" }, "Failed to load system information");
}

export function updateIntegration(payload) {
  return request({ method: "POST", url: "/settings/integrations", data: payload }, "Failed to save integration");
}

export function syncSplunkCache(payload) {
  return request({ method: "POST", url: "/api/splunk/cache/sync", data: payload }, "Cache sync failed");
}

export function disconnectSplunk() {
  return request({ method: "POST", url: "/api/integrations/splunk/disconnect" }, "Failed to disconnect Splunk");
}

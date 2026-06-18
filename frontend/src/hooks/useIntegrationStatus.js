import { useEffect, useRef } from "react";
import { INTEGRATION_CLEARED_EVENT, useIntegrations } from "../context/IntegrationContext";

export function useIntegrationStatus(service) {
  const { status, loading, loaded, forceRefresh, refresh } = useIntegrations();
  const s = status?.[service] || { configured: false, connected: false, error: null };
  const previous = useRef(s);
  const isReady = (value) => {
    if (service === "splunk") {
      return !!(value?.search_connected || value?.connected);
    }
    return !!value?.connected;
  };

  useEffect(() => {
    const before = previous.current;
    if (before?.configured && !isReady(before) && before?.error && isReady(s)) {
      window.dispatchEvent(new CustomEvent(INTEGRATION_CLEARED_EVENT, { detail: { service } }));
    }
    previous.current = s;
  }, [s, service]);

  return { ...s, loaded, loading, refresh: forceRefresh || refresh };
}

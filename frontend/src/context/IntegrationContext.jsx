import { createContext, useContext, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../lib/queryKeys";
import { useIntegrationStatusQuery } from "../hooks/queries/useSettingsQueries";
import { getIntegrationStatus } from "../services/settings.service";

export const INTEGRATION_CLEARED_EVENT = "integration-status-cleared";

const IntegrationContext = createContext(null);

const EMPTY_STATUS = {
  splunk: { configured: false, connected: false, error: null, tested_at: null },
  pfsense: { configured: false, connected: false, error: null, tested_at: null },
};

function serviceReady(service, status) {
  if (service === "splunk") return !!(status?.search_connected || status?.connected);
  return !!status?.connected;
}

function emitClearedEvents(previous, next) {
  if (typeof window === "undefined" || !previous || !next) return;
  Object.keys(next).forEach((service) => {
    const before = previous[service];
    const after = next[service];
    if (before?.configured && !serviceReady(service, before) && before?.error && serviceReady(service, after)) {
      window.dispatchEvent(new CustomEvent(INTEGRATION_CLEARED_EVENT, { detail: { service } }));
    }
  });
}

export function IntegrationProvider({ children }) {
  const queryClient = useQueryClient();
  const previous = useRef(EMPTY_STATUS);
  const [lastChecked, setLastChecked] = useState(null);
  const query = useIntegrationStatusQuery(false, {
    refetchInterval: 30_000,
    retry: 0,
  });

  const status = query.data || EMPTY_STATUS;

  useEffect(() => {
    if (!query.data) return;
    emitClearedEvents(previous.current, query.data);
    previous.current = query.data;
    setLastChecked(new Date());
  }, [query.data]);

  const forceRefresh = async () => {
    const data = await queryClient.fetchQuery({
      queryKey: queryKeys.integrations.status(true),
      queryFn: () => getIntegrationStatus(true),
      staleTime: 0,
    });
    queryClient.setQueryData(queryKeys.integrations.status(false), data);
    return data;
  };

  return (
    <IntegrationContext.Provider
      value={{
        status,
        loading: query.isLoading,
        lastChecked,
        forceRefresh,
        loaded: !query.isLoading,
        refresh: forceRefresh,
        error: query.error?.message || null,
      }}
    >
      {children}
    </IntegrationContext.Provider>
  );
}

export function useIntegrations() {
  const ctx = useContext(IntegrationContext);
  if (!ctx) throw new Error("useIntegrations must be inside IntegrationProvider");
  return ctx;
}

import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { Plugs as Plug, ArrowRight } from "@phosphor-icons/react";
import { INTEGRATION_CLEARED_EVENT } from "../context/IntegrationContext";
import { useIntegrationStatus } from "../hooks/useIntegrationStatus";
import { DismissibleAmberBanner } from "./IntegrationBanner";

const LABELS = {
  splunk: "Splunk",
  pfsense: "pfSense",
};

export default function IntegrationGate({ service, children, fallback }) {
  const status = useIntegrationStatus(service);
  const label = LABELS[service] || service;
  const [, setClearedAt] = useState(null);

  useEffect(() => {
    const onCleared = (event) => {
      if (event.detail?.service === service) setClearedAt(Date.now());
    };
    window.addEventListener(INTEGRATION_CLEARED_EVENT, onCleared);
    return () => window.removeEventListener(INTEGRATION_CLEARED_EVENT, onCleared);
  }, [service]);

  if (status.configured && status.connected) {
    return <>{children}</>;
  }

  if (status.configured && !status.connected) {
    return (
      <>
        <DismissibleAmberBanner
          service={label}
          message={
            status.error
              ? `${label} configured but unreachable: ${status.error}`
              : `${label} is configured but not reachable. Actions using ${label} may fail.`
          }
        />
        {children}
      </>
    );
  }

  if (fallback) return fallback;

  return (
    <div
      style={{
        background: "var(--s2)",
        border: "1px solid var(--b0)",
        borderRadius: 6,
        padding: "32px 24px",
        textAlign: "center",
      }}
    >
      <div style={{ display: "inline-flex", padding: 14, borderRadius: 8,
        background: "var(--ac-d)", color: "var(--ac-h)" }}>
        <Plug size={22} />
      </div>
      <div style={{ fontSize: 15, fontWeight: 600, marginTop: 16, color: "var(--t1)" }}>
        {label} not configured
      </div>
      <div style={{ fontSize: 13, color: "var(--t3)", marginTop: 6 }}>
        Configure {label} in Settings → Integrations to enable this feature.
      </div>
      <Link
        to="/settings/integrations"
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          marginTop: 14,
          background: "var(--ac)",
          color: "white",
          padding: "7px 14px",
          borderRadius: 5,
          fontSize: 13,
          fontWeight: 500,
          textDecoration: "none",
        }}
      >
        Go to Integrations <ArrowRight size={14} />
      </Link>
    </div>
  );
}

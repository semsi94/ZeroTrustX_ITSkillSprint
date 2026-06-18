import { useState } from "react";
import { Warning, X } from "@phosphor-icons/react";
import { Link } from "react-router-dom";

export function AmberBanner({ service, message, onDismiss }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        background: "var(--med-d)",
        border: "1px solid rgba(168,136,26,0.30)",
        color: "var(--med)",
        padding: "9px 14px",
        borderRadius: "var(--r-md)",
        fontSize: 12,
        marginBottom: 12,
      }}
    >
      <Warning size={14} weight="regular" style={{ flexShrink: 0 }} />
      <div style={{ flex: 1, lineHeight: 1.5 }}>
        {message || `${service} is configured but not reachable. Actions using ${service} may fail.`}
      </div>
      <Link
        to="/settings/integrations"
        style={{ color: "var(--med)", fontSize: 11, fontWeight: 600, textDecoration: "underline", flexShrink: 0 }}
      >
        Fix
      </Link>
      {onDismiss && (
        <button
          onClick={onDismiss}
          style={{ background: "transparent", border: "none", color: "inherit", cursor: "pointer", padding: 0, display: "flex" }}
        >
          <X size={13} weight="regular" />
        </button>
      )}
    </div>
  );
}

export function GreenBanner({ message }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        background: "var(--low-d)",
        border: "1px solid rgba(46,143,74,0.28)",
        color: "var(--low)",
        padding: "9px 14px",
        borderRadius: "var(--r-md)",
        fontSize: 12,
        marginBottom: 12,
      }}
    >
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--low)", flexShrink: 0 }} />
      <div style={{ flex: 1 }}>{message}</div>
    </div>
  );
}

export function DismissibleAmberBanner({ service, message }) {
  const [dismissed, setDismissed] = useState(false);
  if (dismissed) return null;
  return <AmberBanner service={service} message={message} onDismiss={() => setDismissed(true)} />;
}

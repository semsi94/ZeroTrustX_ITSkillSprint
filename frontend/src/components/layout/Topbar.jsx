import { useEffect, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useIntegrations } from "../../context/IntegrationContext";

function segmentsFor(pathname) {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 0) return ["Dashboard"];
  return parts.map((p) =>
    p.replace(/-/g, " ").replace(/^\w/, (c) => c.toUpperCase())
  );
}

function IntegrationDot({ label, s }) {
  const isSplunk = label === "Splunk";
  const shortLabel = isSplunk ? "S" : "P";
  const [expanded, setExpanded] = useState(false);
  const timer = useRef(null);

  function handleEnter() { timer.current = setTimeout(() => setExpanded(true), 300); }
  function handleLeave() { clearTimeout(timer.current); setExpanded(false); }

  const managementReady = !!(s?.management_connected || s?.rest_connected || s?.search_connected || s?.connected);
  const searchReady     = !!(s?.search_connected || s?.connected);
  const hecReady        = !!s?.hec_connected;
  const hecConfigured   = !!s?.hec_configured;

  let dotColor = "var(--t4)";
  let bg = "var(--s3)";
  let border = "var(--b1)";
  let textColor = "var(--t3)";
  let statusLine = "Unconfigured";
  let isConnected = false;

  if (isSplunk && searchReady && hecConfigured && hecReady) {
    dotColor = "var(--low)"; bg = "var(--low-d)"; border = "rgba(46,143,74,0.28)";
    textColor = "var(--low)"; statusLine = "API + HEC connected"; isConnected = true;
  } else if (isSplunk && searchReady) {
    dotColor = "var(--med)"; bg = "var(--med-d)"; border = "rgba(168,136,26,0.28)";
    textColor = "var(--med)"; statusLine = hecConfigured ? "API connected · HEC error" : "API connected · HEC not configured";
  } else if (isSplunk && managementReady) {
    dotColor = "var(--med)"; bg = "var(--med-d)"; border = "rgba(168,136,26,0.28)";
    textColor = "var(--med)"; statusLine = "Auth OK · Search API error";
  } else if (!isSplunk && s?.configured && s?.connected) {
    dotColor = "var(--low)"; bg = "var(--low-d)"; border = "rgba(46,143,74,0.28)";
    textColor = "var(--low)"; statusLine = "Connected"; isConnected = true;
  } else if (s?.configured) {
    dotColor = "var(--med)"; bg = "var(--med-d)"; border = "rgba(168,136,26,0.28)";
    textColor = "var(--med)"; statusLine = s?.error ? `Error: ${s.error}` : "Unreachable";
  }

  return (
    <span
      onMouseEnter={handleEnter}
      onMouseLeave={handleLeave}
      title={`${label}: ${statusLine}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        padding: "3px 7px",
        borderRadius: "var(--r-sm)",
        background: bg,
        border: `1px solid ${border}`,
        fontSize: 10,
        fontWeight: 600,
        fontFamily: "var(--font-mono)",
        cursor: "default",
        transition: "background var(--t-fast) var(--ease)",
        userSelect: "none",
        whiteSpace: "nowrap",
        overflow: "hidden",
      }}
    >
      <span
        className={isConnected ? "connected-pulse" : ""}
        style={{
          width: 5, height: 5, borderRadius: "50%",
          background: dotColor, display: "inline-block", flexShrink: 0,
        }}
      />
      <span style={{
        maxWidth: expanded ? 160 : 10,
        overflow: "hidden",
        transition: "max-width 180ms ease",
        color: textColor,
      }}>
        {expanded ? `${label}: ${statusLine}` : shortLabel}
      </span>
    </span>
  );
}

export default function Topbar() {
  const { user } = useAuth();
  const { status } = useIntegrations();
  const { pathname } = useLocation();
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const segments = segmentsFor(pathname);
  const fmtTime = time.toISOString().substring(11, 19) + " UTC";

  return (
    <div style={{
      height: 52,
      background: "var(--s1)",
      borderBottom: "1px solid var(--b1)",
      boxShadow: "var(--el-1)",
      padding: "0 24px",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      position: "sticky",
      top: 0,
      zIndex: 50,
      flexShrink: 0,
    }}>
      {/* Breadcrumb */}
      <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
        {segments.map((seg, i) => (
          <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            {i > 0 && <span style={{ color: "var(--t4)", fontSize: 11 }}>/</span>}
            <span style={{
              fontSize: 12,
              color: i === segments.length - 1 ? "var(--t1)" : "var(--t3)",
              fontWeight: i === segments.length - 1 ? 600 : 400,
            }}>
              {seg}
            </span>
          </span>
        ))}
      </div>

      {/* Right cluster */}
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {/* Integration status dots */}
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <IntegrationDot label="Splunk" s={status?.splunk} />
          <IntegrationDot label="pfSense" s={status?.pfsense} />
        </div>

        <div style={{ width: 1, height: 14, background: "var(--b1)" }} />

        {/* Clock */}
        <div style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          color: "var(--t3)",
          letterSpacing: "0.04em",
        }}>
          {fmtTime}
        </div>

        <div style={{ width: 1, height: 14, background: "var(--b1)" }} />

        {/* User pill */}
        <div style={{
          display: "flex", alignItems: "center", gap: 6,
          background: "var(--s3)",
          border: "1px solid var(--b1)",
          padding: "4px 9px",
          borderRadius: "var(--r-md)",
        }}>
          <span style={{ fontSize: 12, color: "var(--t2)", fontWeight: 500 }}>
            {user?.username || "—"}
          </span>
          <span style={{
            fontSize: 9,
            padding: "1px 5px",
            borderRadius: "var(--r-xs)",
            background: "var(--ac-d)",
            border: "1px solid var(--ac-r)",
            color: "var(--ac-h)",
            textTransform: "uppercase",
            letterSpacing: "0.07em",
            fontWeight: 700,
          }}>
            {user?.role || "user"}
          </span>
        </div>
      </div>
    </div>
  );
}

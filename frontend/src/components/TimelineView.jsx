import { useState } from "react";
import { ArrowSquareOut, CaretRight, MagnifyingGlass } from "@phosphor-icons/react";
import { Link } from "react-router-dom";
import SourceBadge from "./ui/SourceBadge";
import EmptyState from "./ui/EmptyState";
import { sourceMeta } from "../tokens";

function fmt(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return {
    time: d.toISOString().substring(11, 19),
    date: d.toISOString().substring(0, 10),
  };
}

function colorForSource(source) {
  const meta = sourceMeta[String(source || "unknown").toLowerCase()] || sourceMeta.unknown;
  return meta.color;
}

function EventRow({ ev, showIncidentLink }) {
  const [open, setOpen] = useState(false);
  const t = fmt(ev.event_time);
  const sourceColor = colorForSource(ev.source_system);

  return (
    <div
      onClick={() => setOpen((v) => !v)}
      style={{
        position: "relative",
        padding: "12px 0 12px 60px",
        borderBottom: "1px solid rgba(255, 255, 255, 0.04)",
        transition: `background var(--dur-fast) var(--ease-out)`,
        cursor: "pointer",
      }}
      onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255, 255, 255, 0.02)"; }}
      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
    >
      {/* connector dot */}
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          position: "absolute",
          left: 36,
          top: 16,
          background: `${sourceColor}CC`,
          border: `2px solid ${sourceColor}66`,
          boxShadow: `0 0 6px ${sourceColor}40`,
          zIndex: 1,
        }}
      />

      <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
        <div
          style={{
            width: 80,
            flexShrink: 0,
            color: "var(--t3)",
            fontFamily: "var(--font-mono)",
            fontSize: 12,
          }}
        >
          <div style={{ color: "var(--t2)" }}>{typeof t === "object" ? t.time : t}</div>
          {typeof t === "object" && (
            <div style={{ fontSize: 11 }}>{t.date}</div>
          )}
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <SourceBadge source={ev.source_system} short />
            <span style={{ fontSize: 11, color: "var(--t3)", textTransform: "uppercase",
                           letterSpacing: "0.06em" }}>
              {ev.event_type || "event"}
            </span>
          </div>
          <div style={{ fontSize: 14, fontWeight: 500, color: "var(--t1)", marginTop: 4 }}>
            {ev.signature || "—"}
          </div>
          <div style={{ fontSize: 12, color: "var(--t2)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
            {ev.src_ip && (
              <span>
                {ev.src_ip}{ev.dest_ip ? ` → ${ev.dest_ip}` : ""}
              </span>
            )}
            {ev.username && <span style={{ marginLeft: 12 }}>user: {ev.username}</span>}
          </div>
        </div>

        <button
          onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
          className={`chevron-toggle${open ? " open" : ""}`}
          style={{
            background: "transparent",
            border: "none",
            color: "var(--t3)",
            cursor: "pointer",
            alignSelf: "flex-start",
            padding: 4,
            transition: `color var(--dur-fast) var(--ease-out)`,
          }}
        >
          <CaretRight size={16} weight="regular" />
        </button>
      </div>

      {/* CSS-driven expand — uses .timeline-body + .open classes from index.css */}
      <div
        className={`timeline-body${open ? " open" : ""}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          style={{
            background: "var(--s1)",
            border: "1px solid var(--b0)",
            borderLeft: "2px solid var(--ac)",
            borderRadius: "0 6px 6px 0",
            margin: "10px 0 0 0",
            padding: 14,
          }}
        >
          <pre
            className="scrollbar-thin"
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: 12,
              color: "var(--t2)",
              lineHeight: 1.6,
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              maxHeight: 400,
              overflow: "auto",
              margin: 0,
            }}
          >
            {JSON.stringify(ev.raw_payload ?? ev, null, 2)}
          </pre>
          {showIncidentLink && ev.incident_id && (
            <div style={{ marginTop: 10 }}>
              <Link
                to={`/incidents/${ev.incident_id}`}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 4,
                  fontSize: 12,
                  color: "var(--ac-h)",
                  textDecoration: "none",
                }}
              >
                <ArrowSquareOut size={12} weight="regular" /> View Incident #{String(ev.incident_id).slice(0, 8)}
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function TimelineView({ events = [], showIncidentLink = false }) {
  if (!events || events.length === 0) {
    return (
      <EmptyState
        icon={MagnifyingGlass}
        title="No events in timeline"
        subtitle="Events will appear here as alerts are correlated to this incident."
      />
    );
  }
  return (
    <div className="timeline-container">
      {events.map((ev) => (
        <EventRow key={ev.id} ev={ev} showIncidentLink={showIncidentLink} />
      ))}
    </div>
  );
}

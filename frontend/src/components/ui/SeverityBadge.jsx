import { severityMeta } from "../../tokens";
import { useValueChange } from "../../hooks/useValueChange";

function normalize(input) {
  if (typeof input === "number") return input;
  const map = { critical: 5, high: 4, medium: 3, low: 2, info: 1, informational: 1 };
  const key = String(input || "unknown").toLowerCase();
  return map[key] || 0;
}

// Flat badge borders keyed to severity level
const BADGE_BORDERS = {
  5: "rgba(207,74,74,0.30)",
  4: "rgba(192,120,40,0.30)",
  3: "rgba(168,136,26,0.30)",
  2: "rgba(46,143,74,0.30)",
  1: "rgba(61,126,245,0.30)",
  0: "rgba(94,107,128,0.25)",
};

export default function SeverityBadge({ severity }) {
  const s = normalize(severity);
  const meta = severityMeta[s] || { label: "Unknown", color: "var(--t3)", bg: "var(--s3)" };
  const pulse = useValueChange(s);

  return (
    <span
      className={pulse ? "badge-updated" : ""}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        color: meta.color,
        background: meta.bg,
        border: `1px solid ${BADGE_BORDERS[s] || BADGE_BORDERS[0]}`,
        padding: "2px 7px",
        borderRadius: "var(--r-xs)",
        fontSize: 10,
        textTransform: "uppercase",
        letterSpacing: "0.09em",
        fontWeight: 700,
        whiteSpace: "nowrap",
        lineHeight: 1.5,
      }}
    >
      <span
        style={{
          width: 5, height: 5, borderRadius: "50%", background: meta.color,
          display: "inline-block", flexShrink: 0,
        }}
      />
      {meta.label}
    </span>
  );
}

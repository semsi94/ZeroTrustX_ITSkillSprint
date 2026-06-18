import { statusMeta } from "../../tokens";
import { useValueChange } from "../../hooks/useValueChange";

export default function StatusBadge({ status }) {
  const meta = statusMeta[status] || { label: status || "Unknown", color: "var(--t3)" };
  const pulse = useValueChange(status);

  return (
    <span
      className={pulse ? "badge-updated" : ""}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        color: meta.color,
        background: `${meta.color}1A`,
        border: `1px solid ${meta.color}33`,
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
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: meta.color, flexShrink: 0 }} />
      {meta.label}
    </span>
  );
}

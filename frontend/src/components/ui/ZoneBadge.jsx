import { zoneMeta } from "../../tokens";

const ZONE_PALETTE = {
  dmz:        { bg: "var(--high-d)",  border: "rgba(192,120,40,0.28)",  color: "var(--high)"       },
  internal:   { bg: "var(--info-d)",  border: "rgba(61,126,245,0.28)",  color: "var(--ac)"         },
  management: { bg: "rgba(123,98,184,0.13)", border: "rgba(123,98,184,0.28)", color: "var(--st-monitor)" },
  internet:   { bg: "var(--crit-d)", border: "rgba(207,74,74,0.28)",   color: "var(--crit)"       },
  unknown:    { bg: "var(--s3)",      border: "var(--b1)",              color: "var(--t3)"         },
};

export default function ZoneBadge({ zone }) {
  const key = String(zone || "unknown").toLowerCase();
  const meta = zoneMeta[key] || zoneMeta.unknown;
  const palette = ZONE_PALETTE[key] || ZONE_PALETTE.unknown;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        color: palette.color,
        background: palette.bg,
        border: `1px solid ${palette.border}`,
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
      {meta.label}
    </span>
  );
}

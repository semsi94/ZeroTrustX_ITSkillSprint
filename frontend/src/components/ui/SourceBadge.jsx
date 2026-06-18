import { sourceMeta } from "../../tokens";

const SOURCE_PALETTE = {
  suricata: { bg: "var(--high-d)",  border: "rgba(192,120,40,0.28)",  color: "var(--high)"  },
  pfsense:  { bg: "var(--info-d)",  border: "rgba(61,126,245,0.28)",  color: "var(--ac)"    },
  web:      { bg: "var(--low-d)",   border: "rgba(46,143,74,0.28)",   color: "var(--low)"   },
  windows:  { bg: "var(--info-d)",  border: "rgba(61,126,245,0.28)",  color: "var(--ac)"    },
  unknown:  { bg: "var(--s3)",      border: "var(--b1)",              color: "var(--t3)"    },
};

export default function SourceBadge({ source, short = false }) {
  const key = String(source || "unknown").toLowerCase();
  const meta = sourceMeta[key] || sourceMeta.unknown;
  const palette = SOURCE_PALETTE[key] || SOURCE_PALETTE.unknown;

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
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
      title={meta.label}
    >
      <span style={{
        fontSize: 9,
        fontFamily: "var(--font-mono)",
        fontWeight: 700,
      }}>
        {meta.short}
      </span>
      {!short && <span>{meta.label}</span>}
    </span>
  );
}

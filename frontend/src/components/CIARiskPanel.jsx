// CIA Risk Panel — horizontal bars, Neo-Industrial Dark.
// Three rows: Confidentiality / Integrity / Availability

const CIA = [
  {
    key: "c",
    label: "Confidentiality",
    abbr: "C",
    icon: (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" />
        <path d="M7 11V7a5 5 0 0110 0v4" />
      </svg>
    ),
    color: "#5B7FE5",
  },
  {
    key: "i",
    label: "Integrity",
    abbr: "I",
    icon: (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" />
      </svg>
    ),
    color: "#C07828",
  },
  {
    key: "a",
    label: "Availability",
    abbr: "A",
    icon: (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
    color: "#A8881A",
  },
];

function riskLabel(score) {
  if (score >= 70) return { label: "Critical", color: "var(--crit)" };
  if (score >= 45) return { label: "High",     color: "var(--high)" };
  if (score >= 20) return { label: "Medium",   color: "var(--med)"  };
  return                  { label: "Low",      color: "var(--low)"  };
}

function CIARow({ meta, score }) {
  const pct  = Math.max(0, Math.min(100, score || 0));
  const risk = riskLabel(pct);
  const active = pct > 0;

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "9px 10px",
      background: active ? `${meta.color}0D` : "transparent",
      border: `1px solid ${active ? `${meta.color}22` : "var(--b0)"}`,
      borderRadius: "var(--r-md)",
      transition: "background 400ms ease, border-color 400ms ease",
    }}>
      {/* Icon badge */}
      <div style={{
        width: 22, height: 22, borderRadius: "var(--r-sm)",
        background: active ? `${meta.color}18` : "var(--s3)",
        border: `1px solid ${active ? `${meta.color}28` : "var(--b1)"}`,
        display: "flex", alignItems: "center", justifyContent: "center",
        flexShrink: 0,
        color: active ? meta.color : "var(--t4)",
        transition: "background 400ms ease, color 400ms ease",
      }}>
        {meta.icon}
      </div>

      {/* Label */}
      <div style={{
        width: 86,
        fontSize: 11,
        fontWeight: 600,
        color: active ? "var(--t2)" : "var(--t4)",
        whiteSpace: "nowrap",
        flexShrink: 0,
        transition: "color 400ms ease",
      }}>
        {meta.label}
      </div>

      {/* Bar track */}
      <div style={{
        flex: 1,
        height: 5,
        background: "var(--s3)",
        border: "1px solid var(--b0)",
        borderRadius: 3,
        overflow: "hidden",
        minWidth: 0,
      }}>
        <div style={{
          height: "100%",
          width: `${pct}%`,
          background: active ? meta.color : "transparent",
          borderRadius: 3,
          transition: "width 700ms cubic-bezier(0.22,1,0.36,1)",
        }} />
      </div>

      {/* Score */}
      <div style={{
        width: 28,
        fontSize: 11,
        fontFamily: "var(--font-mono)",
        fontWeight: 600,
        textAlign: "right",
        color: active ? risk.color : "var(--t4)",
        flexShrink: 0,
        transition: "color 400ms ease",
      }}>
        {pct}
      </div>

      {/* Risk badge */}
      <div style={{
        fontSize: 9,
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.09em",
        color: active ? risk.color : "var(--t4)",
        background: active ? `${risk.color}14` : "transparent",
        border: `1px solid ${active ? `${risk.color}28` : "var(--b0)"}`,
        padding: "1px 6px",
        borderRadius: "var(--r-xs)",
        flexShrink: 0,
        whiteSpace: "nowrap",
        transition: "all 400ms ease",
        minWidth: 44,
        textAlign: "center",
      }}>
        {active ? risk.label : "No data"}
      </div>
    </div>
  );
}

export default function CIARiskPanel({ scores = {} }) {
  const c = Math.round(scores.c || 0);
  const i = Math.round(scores.i || 0);
  const a = Math.round(scores.a || 0);
  const avg = Math.round((c + i + a) / 3);
  const avgRisk = riskLabel(avg);

  return (
    <div style={{
      background: "var(--s2)",
      border: "1px solid var(--b1)",
      borderRadius: "var(--r-lg)",
      boxShadow: "var(--el-1)",
      padding: "16px 18px",
      height: "100%",
      boxSizing: "border-box",
      display: "flex",
      flexDirection: "column",
      gap: 10,
    }}>
      {/* Header */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexShrink: 0,
      }}>
        <div>
          <div style={{
            fontSize: 10,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.10em",
            color: "var(--t3)",
          }}>
            CIA Risk
          </div>
          <div style={{ fontSize: 10, color: "var(--t4)", marginTop: 1 }}>
            Live threat impact
          </div>
        </div>

        {avg > 0 && (
          <span style={{
            fontSize: 10,
            fontFamily: "var(--font-mono)",
            fontWeight: 700,
            color: avgRisk.color,
            background: `${avgRisk.color}14`,
            border: `1px solid ${avgRisk.color}28`,
            padding: "2px 7px",
            borderRadius: "var(--r-xs)",
          }}>
            AVG {avg}
          </span>
        )}
      </div>

      {/* Three CIA rows */}
      <div style={{
        display: "flex",
        flexDirection: "column",
        gap: 6,
        flex: 1,
        justifyContent: "center",
      }}>
        {CIA.map((meta) => (
          <CIARow
            key={meta.key}
            meta={meta}
            score={meta.key === "c" ? c : meta.key === "i" ? i : a}
          />
        ))}
      </div>
    </div>
  );
}

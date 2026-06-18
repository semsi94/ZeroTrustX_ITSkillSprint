const LEVELS = {
  0: { label: "None", color: "var(--low)" },
  1: { label: "Low", color: "var(--med)" },
  2: { label: "High", color: "var(--crit)" },
};

const TRIGGERS = {
  c: {
    high: ["credential", "login", "auth", "exfil", "dump", "spray", "password", "secret", "token"],
    low: ["scan", "recon", "enum", "probe"],
    impact: {
      2: "Possible unauthorized data access or credential exposure",
      1: "Reconnaissance consistent with data-gathering intent",
      0: "No confidentiality signal detected",
    },
  },
  i: {
    high: ["inject", "exploit", "tamper", "modify", "exec", "rce", "shell", "overflow", "traversal"],
    low: ["admin", "config", "change", "write"],
    impact: {
      2: "Potential code execution or data tampering",
      1: "Administrative or configuration activity observed",
      0: "No integrity signal detected",
    },
  },
  a: {
    high: ["flood", "ddos", "dos", "burst", "spike", "crash", "denial", "unavailable"],
    low: ["scan", "probe", "sweep", "ping", "brute"],
    impact: {
      2: "Active denial-of-service pattern",
      1: "Probing that can precede availability impact",
      0: "No availability signal detected",
    },
  },
};

function matchedKeywords(axis, signature) {
  const trigger = TRIGGERS[axis];
  const text = String(signature || "").toLowerCase();
  const hits = new Set();
  [...trigger.high, ...trigger.low].forEach((keyword) => {
    if (text.includes(keyword)) hits.add(keyword);
  });
  return [...hits];
}

function Column({ axis, title, value, signature }) {
  const meta = LEVELS[value] || LEVELS[0];
  const triggers = matchedKeywords(axis, signature);
  return (
    <div
      style={{
        background: "var(--s2)",
        border: "1px solid var(--b1)",
        borderRadius: 6,
        padding: 16,
        flex: 1,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
        <div style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--t3)" }}>
          {title}
        </div>
        <div
          style={{
            color: meta.color,
            background: "var(--s1)",
            border: `1px solid ${meta.color}55`,
            borderRadius: 4,
            padding: "2px 8px",
            fontSize: 11,
            fontWeight: 600,
            textTransform: "uppercase",
            whiteSpace: "nowrap",
          }}
        >
          {value} / {meta.label}
        </div>
      </div>
      <div style={{ marginTop: 12, fontSize: 12, color: "var(--t2)" }}>
        <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
          Triggered by
        </div>
        {triggers.length === 0 ? (
          <div style={{ color: "var(--t3)" }}>-</div>
        ) : (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {triggers.map((trigger) => (
              <span
                key={trigger}
                style={{
                  background: "var(--s3)",
                  border: "1px solid var(--b1)",
                  padding: "2px 6px",
                  borderRadius: 4,
                  fontSize: 11,
                  fontFamily: "var(--font-mono)",
                  color: "var(--t2)",
                }}
              >
                {trigger}
              </span>
            ))}
          </div>
        )}
      </div>
      <div style={{ marginTop: 12, fontSize: 12, color: "var(--t3)", lineHeight: 1.5 }}>
        {TRIGGERS[axis].impact[value]}
      </div>
    </div>
  );
}

export default function CIAPanel({ incident }) {
  const signature = `${incident?.title || ""} ${incident?.alerts?.[0]?.signature || ""}`;
  return (
    <div style={{ display: "flex", gap: 12 }}>
      <Column axis="c" title="Confidentiality" value={incident?.cia_c ?? 0} signature={signature} />
      <Column axis="i" title="Integrity" value={incident?.cia_i ?? 0} signature={signature} />
      <Column axis="a" title="Availability" value={incident?.cia_a ?? 0} signature={signature} />
    </div>
  );
}

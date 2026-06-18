export default function Tabs({ tabs, value, onChange }) {
  return (
    <div
      style={{
        display: "flex",
        gap: 0,
        borderBottom: "1px solid var(--b1)",
        marginBottom: 16,
      }}
    >
      {tabs.map((t) => {
        const active = value === t.value;
        return (
          <button
            key={t.value}
            onClick={() => onChange(t.value)}
            style={{
              background: "transparent",
              border: "none",
              borderBottom: active
                ? "2px solid var(--ac)"
                : "2px solid transparent",
              color: active ? "var(--ac-h)" : "var(--t3)",
              padding: "9px 16px",
              cursor: "pointer",
              fontSize: 12,
              fontWeight: active ? 600 : 400,
              marginBottom: -1,
              letterSpacing: "0.01em",
              transition: "color var(--t-fast) var(--ease), border-color var(--t-fast) var(--ease), background var(--t-fast) var(--ease)",
              fontFamily: "inherit",
              borderRadius: "var(--r-sm) var(--r-sm) 0 0",
            }}
            onMouseEnter={(e) => {
              if (!active) {
                e.currentTarget.style.color = "var(--t1)";
                e.currentTarget.style.background = "var(--s3)";
              }
            }}
            onMouseLeave={(e) => {
              if (!active) {
                e.currentTarget.style.color = "var(--t3)";
                e.currentTarget.style.background = "transparent";
              }
            }}
          >
            {t.label}
            {typeof t.count === "number" && (
              <span
                style={{
                  marginLeft: 6,
                  fontSize: 10,
                  color: "var(--t3)",
                  background: "var(--s3)",
                  border: "1px solid var(--b1)",
                  padding: "1px 6px",
                  borderRadius: 8,
                }}
              >
                {t.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

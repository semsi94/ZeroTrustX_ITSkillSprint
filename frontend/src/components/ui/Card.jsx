// Card — Neo-Industrial Dark surface panels.
// Variants: default, elevated, inset (well), flat, critical

export default function Card({
  children,
  className = "",
  style = {},
  hover = false,
  onClick,
  well = false,      // inset / lower surface
  flat = false,      // no shadow, just border
  elevated = false,  // higher elevation
  critical = false,  // severity left border
}) {
  const getBase = () => {
    if (critical) return {
      background: "var(--s2)",
      borderRadius: "var(--r-lg)",
      border: "1px solid rgba(207,74,74,0.30)",
      borderLeft: "3px solid var(--crit)",
      boxShadow: "none",
      padding: "16px 20px",
    };
    if (elevated) return {
      background: "var(--s3)",
      borderRadius: "var(--r-lg)",
      border: "1px solid var(--b1)",
      boxShadow: "var(--el-2)",
      padding: "16px 20px",
    };
    if (flat) return {
      background: "var(--s2)",
      borderRadius: "var(--r-lg)",
      border: "1px solid var(--b1)",
      boxShadow: "none",
      padding: "16px 20px",
    };
    if (well) return {
      background: "var(--s1)",
      borderRadius: "var(--r-lg)",
      border: "1px solid var(--b0)",
      boxShadow: "none",
      padding: "16px 20px",
    };
    return {
      background: "var(--s2)",
      borderRadius: "var(--r-lg)",
      border: "1px solid var(--b1)",
      boxShadow: "var(--el-1)",
      padding: "16px 20px",
    };
  };

  const base = {
    ...getBase(),
    transition: "box-shadow var(--t-base) var(--ease), border-color var(--t-base) var(--ease), background var(--t-fast) var(--ease)",
    cursor: hover || onClick ? "pointer" : undefined,
    ...style,
  };

  return (
    <div
      onClick={onClick}
      className={className}
      style={base}
      onMouseEnter={(e) => {
        if ((hover || onClick) && !critical) {
          e.currentTarget.style.boxShadow = "var(--el-2)";
          e.currentTarget.style.borderColor = "var(--b2)";
        }
      }}
      onMouseLeave={(e) => {
        if ((hover || onClick) && !critical) {
          e.currentTarget.style.boxShadow = elevated ? "var(--el-2)" : flat || well ? "none" : "var(--el-1)";
          e.currentTarget.style.borderColor = well ? "var(--b0)" : "var(--b1)";
        }
      }}
    >
      {children}
    </div>
  );
}

export function CardLabel({ children, style = {} }) {
  return (
    <div
      style={{
        fontSize: 10,
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.10em",
        color: "var(--t3)",
        marginBottom: 10,
        ...style,
      }}
    >
      {children}
    </div>
  );
}

export function SectionHeader({ children, actions, style = {} }) {
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: 12,
      ...style,
    }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: "var(--t1)" }}>{children}</div>
      {actions && <div style={{ display: "flex", gap: 6, alignItems: "center" }}>{actions}</div>}
    </div>
  );
}

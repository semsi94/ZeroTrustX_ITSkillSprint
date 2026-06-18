import { useState } from "react";

// ── Spinner ───────────────────────────────────────────────────────────
function Spinner({ size = 12 }) {
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        border: "1.5px solid rgba(255,255,255,0.18)",
        borderTopColor: "currentColor",
        display: "inline-block",
        flexShrink: 0,
        animation: "spin 0.55s linear infinite",
      }}
    />
  );
}

// ── Variant definitions ────────────────────────────────────────────────
const VARIANTS = {
  primary: {
    bg:            "var(--ac)",
    color:         "#FFFFFF",
    border:        "1px solid rgba(61,126,245,0.40)",
    shadow:        "var(--el-1)",
    pressedShadow: "inset 0 1px 3px rgba(0,0,0,0.30)",
    hoverBg:       "var(--ac-h)",
  },
  secondary: {
    bg:            "var(--s3)",
    color:         "var(--t1)",
    border:        "1px solid var(--b2)",
    shadow:        "var(--el-1)",
    pressedShadow: "inset 0 1px 3px rgba(0,0,0,0.30)",
    hoverBg:       "var(--s4)",
  },
  danger: {
    bg:            "rgba(207,74,74,0.90)",
    color:         "#FFFFFF",
    border:        "1px solid rgba(207,74,74,0.55)",
    shadow:        "var(--el-1)",
    pressedShadow: "inset 0 1px 3px rgba(0,0,0,0.30)",
    hoverBg:       "rgba(220,60,60,0.96)",
  },
  ghost: {
    bg:            "transparent",
    color:         "var(--t2)",
    border:        "1px solid transparent",
    shadow:        "none",
    pressedShadow: "none",
    hoverBg:       "var(--s3)",
  },
  tactical: {
    bg:            "var(--ac-d)",
    color:         "var(--ac-h)",
    border:        "1px solid var(--ac-r)",
    shadow:        "var(--el-1)",
    pressedShadow: "inset 0 1px 3px rgba(0,0,0,0.30)",
    hoverBg:       "rgba(61,126,245,0.18)",
  },
};

const SIZES = {
  xs: { padding: "4px 10px",  fontSize: 11 },
  sm: { padding: "5px 12px",  fontSize: 11 },
  md: { padding: "7px 16px",  fontSize: 13 },
  lg: { padding: "10px 22px", fontSize: 14 },
};

export default function Button({
  children,
  variant = "secondary",
  size = "md",
  disabled = false,
  loading = false,
  onClick,
  type = "button",
  className = "",
  style = {},
  title,
  fullWidth = false,
}) {
  const [pressed, setPressed] = useState(false);
  const v = VARIANTS[variant] || VARIANTS.secondary;
  const s = SIZES[size] || SIZES.md;

  return (
    <button
      type={type}
      disabled={disabled || loading}
      onClick={onClick}
      title={title}
      onMouseDown={() => setPressed(true)}
      onMouseUp={() => setPressed(false)}
      onMouseLeave={(e) => {
        setPressed(false);
        if (!disabled && !loading) {
          e.currentTarget.style.background = v.bg;
          e.currentTarget.style.boxShadow = v.shadow;
        }
      }}
      onMouseEnter={(e) => {
        if (!disabled && !loading) {
          e.currentTarget.style.background = v.hoverBg;
        }
      }}
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: s.padding,
        fontSize: s.fontSize,
        fontWeight: 500,
        fontFamily: "var(--font-sans)",
        letterSpacing: "0.01em",
        background: v.bg,
        color: v.color,
        border: v.border,
        borderRadius: "var(--r-md)",
        boxShadow: pressed ? v.pressedShadow : v.shadow,
        cursor: disabled || loading ? "not-allowed" : "pointer",
        opacity: disabled ? 0.42 : 1,
        whiteSpace: "nowrap",
        width: fullWidth ? "100%" : undefined,
        transition: "background var(--t-fast) var(--ease), box-shadow var(--t-fast) var(--ease), opacity var(--t-fast) var(--ease)",
        userSelect: "none",
        lineHeight: 1.25,
        flexShrink: fullWidth ? undefined : 0,
        ...style,
      }}
    >
      {loading && <Spinner size={s.fontSize} />}
      {children}
    </button>
  );
}

export function IconButton({ children, onClick, title, style = {}, active = false }) {
  return (
    <button
      onClick={onClick}
      title={title}
      style={{
        width: 30,
        height: 30,
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        background: active ? "var(--ac-d)" : "transparent",
        border: active ? "1px solid var(--ac-r)" : "1px solid transparent",
        borderRadius: "var(--r-md)",
        color: active ? "var(--ac-h)" : "var(--t2)",
        cursor: "pointer",
        transition: "background var(--t-fast) var(--ease), color var(--t-fast) var(--ease), border-color var(--t-fast) var(--ease)",
        flexShrink: 0,
        ...style,
      }}
      onMouseEnter={(e) => {
        if (!active) {
          e.currentTarget.style.background = "var(--s3)";
          e.currentTarget.style.color = "var(--t1)";
        }
      }}
      onMouseLeave={(e) => {
        if (!active) {
          e.currentTarget.style.background = "transparent";
          e.currentTarget.style.color = "var(--t2)";
        }
      }}
    >
      {children}
    </button>
  );
}

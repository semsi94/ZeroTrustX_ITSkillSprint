import { useMemo } from "react";
import { ResponsiveContainer, AreaChart, Area } from "recharts";
import { TrendUp, TrendDown, Minus } from "@phosphor-icons/react";
import { useValueChange } from "../hooks/useValueChange";

const FALLBACK_SPARK = Array.from({ length: 12 }, (_, i) => ({ i, v: 0 }));

export default function KPICard({
  label,
  value,
  unit,
  delta,
  sparkData,
  color = "var(--ac-h)",
}) {
  const animating = useValueChange(value, 200);

  let deltaColor = "var(--t3)";
  let DeltaIcon = Minus;
  if (typeof delta === "number" && delta !== 0) {
    DeltaIcon = delta > 0 ? TrendUp : TrendDown;
    deltaColor = delta > 0 ? "var(--crit)" : "var(--low)";
  }

  const data = useMemo(
    () => (sparkData && sparkData.length > 0 ? sparkData : FALLBACK_SPARK),
    [sparkData],
  );

  return (
    <div
      style={{
        background: "var(--s2)",
        border: animating ? "1px solid rgba(168,136,26,0.32)" : "1px solid var(--b1)",
        borderRadius: "var(--r-lg)",
        boxShadow: "var(--el-1)",
        padding: "14px 16px",
        minHeight: 96,
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        overflow: "visible",
        transition: "border-color var(--t-base) var(--ease)",
      }}
    >
      {/* Label */}
      <div style={{
        fontSize: 10,
        textTransform: "uppercase",
        letterSpacing: "0.10em",
        color: "var(--t3)",
        fontWeight: 700,
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis",
      }}>
        {label}
      </div>

      {/* Value */}
      <div
        className={animating ? "number-update" : ""}
        style={{
          fontSize: "1.9rem",
          fontWeight: 700,
          lineHeight: 1,
          fontFamily: "var(--font-mono)",
          color: "var(--t1)",
          display: "flex",
          alignItems: "baseline",
          gap: 4,
          whiteSpace: "nowrap",
          letterSpacing: "-0.02em",
          marginTop: 6,
        }}
      >
        {value}
        {unit && (
          <span style={{ fontSize: 12, color: "var(--t3)", fontFamily: "var(--font-sans)", fontWeight: 400 }}>
            {unit}
          </span>
        )}
      </div>

      {/* Sparkline + delta */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
        <div style={{ flex: 1, height: 20 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id={`kpi-g-${label}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={color} stopOpacity={0.18} />
                  <stop offset="100%" stopColor={color} stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="v"
                stroke={color}
                strokeOpacity={0.65}
                strokeWidth={1.5}
                fill={`url(#kpi-g-${label})`}
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div style={{
          display: "flex",
          alignItems: "center",
          gap: 3,
          fontSize: 11,
          color: deltaColor,
          flexShrink: 0,
          fontWeight: 600,
        }}>
          <DeltaIcon size={11} weight="bold" />
          {typeof delta === "number"
            ? `${delta > 0 ? "+" : ""}${delta}%`
            : "—"}
        </div>
      </div>
    </div>
  );
}

export default function Skeleton({ width = "100%", height = 14, className = "", style = {} }) {
  return (
    <div
      className={`skeleton ${className}`}
      style={{ width, height, ...style }}
    />
  );
}

// Stable widths by index — no Math.random() in render
const ROW_WIDTHS = ["92%", "78%", "85%", "70%", "88%", "75%", "82%", "68%", "90%", "73%"];

export function SkeletonRows({ rows = 5, height = 16 }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} height={height} width={ROW_WIDTHS[i % ROW_WIDTHS.length]} />
      ))}
    </div>
  );
}

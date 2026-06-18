export default function PageHeader({ title, subtitle, actions }) {
  return (
    <div style={{ padding: "20px 24px 0 24px", flexShrink: 0 }}>
      <div style={{
        display: "flex",
        alignItems: "flex-end",
        justifyContent: "space-between",
        gap: 16,
        minWidth: 0,
      }}>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{
            fontSize: 19,
            fontWeight: 700,
            color: "var(--t1)",
            lineHeight: 1.25,
            letterSpacing: "-0.02em",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}>
            {title}
          </div>
          {subtitle && (
            <div style={{
              fontSize: 12,
              color: "var(--t3)",
              marginTop: 3,
              fontWeight: 400,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}>
              {subtitle}
            </div>
          )}
        </div>
        {actions && (
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
            {actions}
          </div>
        )}
      </div>
      <div style={{ height: 1, background: "var(--b0)", marginTop: 14 }} />
    </div>
  );
}

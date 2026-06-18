import { Tray } from "@phosphor-icons/react";

export default function EmptyState({
  icon: Icon = Tray,
  title = "Nothing here",
  subtitle,
  action,
}) {
  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: "44px 24px",
      textAlign: "center",
    }}>
      {/* Icon tile */}
      <div style={{
        width: 48,
        height: 48,
        borderRadius: "var(--r-lg)",
        background: "var(--s3)",
        border: "1px solid var(--b1)",
        boxShadow: "none",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        marginBottom: 14,
        flexShrink: 0,
      }}>
        <Icon size={20} weight="regular" color="var(--t4)" />
      </div>

      <div style={{ color: "var(--t2)", fontSize: 13, fontWeight: 600, lineHeight: 1.4 }}>
        {title}
      </div>

      {subtitle && (
        <div style={{
          color: "var(--t3)",
          fontSize: 11,
          marginTop: 6,
          maxWidth: 380,
          lineHeight: 1.6,
        }}>
          {subtitle}
        </div>
      )}

      {action && <div style={{ marginTop: 18 }}>{action}</div>}
    </div>
  );
}

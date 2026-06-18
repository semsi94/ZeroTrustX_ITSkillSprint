import { NavLink, useNavigate } from "react-router-dom";
import {
  Gauge,
  Warning,
  MagnifyingGlass,
  HardDrives,
  ShieldStar,
  ChartBar,
  Sliders,
  SignOut,
  List,
  X as PhosphorX,
} from "@phosphor-icons/react";
import { useAuth } from "../../context/AuthContext";
import { useIntegrations } from "../../context/IntegrationContext";

const groups = [
  {
    label: "MONITOR",
    items: [
      { to: "/", label: "Dashboard", icon: Gauge, end: true },
      { to: "/incidents", label: "Incidents", icon: Warning },
    ],
  },
  {
    label: "INVESTIGATE",
    items: [
      { to: "/investigation", label: "Investigation", icon: MagnifyingGlass },
      { to: "/assets", label: "Assets", icon: HardDrives },
    ],
  },
  {
    label: "RESPOND",
    items: [
      { to: "/response", label: "Response", icon: ShieldStar },
    ],
  },
  {
    label: "REPORT",
    items: [
      { to: "/reports", label: "Reports", icon: ChartBar },
    ],
  },
];

function NavItem({ to, label, icon: Icon, end, badge, collapsed }) {
  return (
    <NavLink
      to={to}
      end={end}
      title={collapsed ? label : undefined}
      style={({ isActive }) => ({
        height: 36,
        padding: collapsed ? "0" : "0 14px",
        display: "flex",
        alignItems: "center",
        justifyContent: collapsed ? "center" : "flex-start",
        gap: 9,
        color: isActive ? "var(--ac-h)" : "var(--t2)",
        background: isActive ? "var(--ac-d)" : "transparent",
        borderLeft: isActive ? "2px solid var(--ac)" : "2px solid transparent",
        fontSize: 12,
        fontWeight: isActive ? 600 : 400,
        textDecoration: "none",
        position: "relative",
        letterSpacing: "0.01em",
        transition: "color var(--t-fast) var(--ease), background var(--t-fast) var(--ease)",
      })}
      onMouseEnter={(e) => {
        const active = e.currentTarget.getAttribute("aria-current") === "page";
        if (!active) {
          e.currentTarget.style.color = "var(--t1)";
          e.currentTarget.style.background = "var(--s3)";
        }
      }}
      onMouseLeave={(e) => {
        const active = e.currentTarget.getAttribute("aria-current") === "page";
        if (!active) {
          e.currentTarget.style.color = "var(--t2)";
          e.currentTarget.style.background = "transparent";
        }
      }}
    >
      {({ isActive }) => (
        <>
          <Icon
            size={15}
            weight={isActive ? "bold" : "regular"}
            color={isActive ? "var(--ac-h)" : "var(--t3)"}
          />
          {!collapsed && <span style={{ flex: 1, lineHeight: 1 }}>{label}</span>}
          {badge}
        </>
      )}
    </NavLink>
  );
}

function NavLabel({ children, collapsed }) {
  if (collapsed) return <div style={{ height: 10 }} />;
  return (
    <div style={{
      fontSize: 9,
      fontWeight: 700,
      textTransform: "uppercase",
      letterSpacing: "0.14em",
      color: "var(--t4)",
      padding: "12px 16px 4px",
    }}>
      {children}
    </div>
  );
}

export default function Sidebar({ collapsed = false, onToggle }) {
  const { user, logout } = useAuth();
  const { status } = useIntegrations();
  const navigate = useNavigate();
  const canManageSettings = user?.role === "admin";

  const anyUnconfigured =
    (status?.splunk && !status.splunk.configured) ||
    (status?.pfsense && !status.pfsense.configured);

  const initials = (user?.username || "?")
    .split(/[\s_.-]/)
    .map((s) => s[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  const settingsBadge = anyUnconfigured ? (
    <span style={{
      position: "absolute", top: 8, right: 10,
      width: 6, height: 6, borderRadius: "50%",
      background: "var(--crit)",
      border: "2px solid var(--s1)",
    }} />
  ) : null;

  return (
    <aside
      className="sidebar"
      style={{
        position: "fixed",
        top: 0, left: 0,
        width: collapsed ? 52 : 220,
        height: "100vh",
        background: "var(--s1)",
        borderRight: "1px solid var(--b1)",
        boxShadow: "none",
        zIndex: 100,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        transition: "width 160ms var(--ease)",
      }}
    >
      {/* Logo bar */}
      <div style={{
        height: 52,
        padding: collapsed ? "0 8px" : "0 14px",
        display: "flex",
        alignItems: "center",
        justifyContent: collapsed ? "center" : "space-between",
        gap: 8,
        borderBottom: "1px solid var(--b1)",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 9, minWidth: 0 }}>
          {/* Shield logo mark */}
          <div style={{
            width: 28, height: 28,
            borderRadius: "var(--r-md)",
            background: "var(--ac)",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 2px 6px rgba(0,0,0,0.40)",
            flexShrink: 0,
          }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
              stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" />
              <line x1="8" y1="12" x2="16" y2="12" />
            </svg>
          </div>

          {!collapsed && (
            <div style={{
              fontSize: 13,
              fontWeight: 700,
              color: "var(--t1)",
              letterSpacing: "-0.02em",
              whiteSpace: "nowrap",
            }}>
              ZeroTrustX
            </div>
          )}
        </div>

        {!collapsed ? (
          <button
            onClick={onToggle}
            title="Collapse sidebar"
            style={{
              background: "transparent", border: "none",
              color: "var(--t3)", cursor: "pointer",
              display: "flex", padding: 4, borderRadius: "var(--r-sm)",
              transition: "color var(--t-fast) var(--ease)",
              flexShrink: 0,
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--t1)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--t3)"; }}
          >
            <PhosphorX size={14} weight="bold" />
          </button>
        ) : (
          <button
            onClick={onToggle}
            title="Expand sidebar"
            style={{
              background: "var(--s3)",
              border: "1px solid var(--b1)",
              borderRadius: "var(--r-md)",
              color: "var(--t2)", cursor: "pointer",
              width: 28, height: 28,
              display: "flex", alignItems: "center", justifyContent: "center",
              transition: "background var(--t-fast) var(--ease)",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--s4)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "var(--s3)"; }}
          >
            <List size={13} weight="bold" />
          </button>
        )}
      </div>

      {/* Nav */}
      <div className="scroll-area scrollbar-thin" style={{ flex: 1, paddingBottom: 8 }}>
        {groups.map((g, idx) => (
          <div key={g.label}>
            {idx > 0 && (
              <div style={{ height: 1, background: "var(--b0)", margin: "6px 0" }} />
            )}
            <NavLabel collapsed={collapsed}>{g.label}</NavLabel>
            {g.items.map((it) => (
              <NavItem key={it.to} {...it} collapsed={collapsed} />
            ))}
          </div>
        ))}

        {canManageSettings && (
          <>
            <div style={{ height: 1, background: "var(--b0)", margin: "6px 0" }} />
            <NavLabel collapsed={collapsed}>CONFIG</NavLabel>
            <NavItem
              to="/settings/integrations"
              label="Settings"
              icon={Sliders}
              badge={settingsBadge}
              collapsed={collapsed}
            />
          </>
        )}
      </div>

      {/* User block */}
      <div style={{
        background: "var(--s0)",
        borderTop: "1px solid var(--b1)",
        padding: collapsed ? "10px 8px" : "10px 14px",
        display: "flex",
        alignItems: "center",
        gap: 9,
        flexShrink: 0,
      }}>
        <button
          type="button"
          onClick={() => navigate("/account")}
          title="Account settings"
          style={{
            width: 28, height: 28, borderRadius: "50%",
            background: "var(--ac-d)",
            border: "1px solid var(--ac-r)",
            color: "var(--ac-h)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontWeight: 700, fontSize: 10, fontFamily: "var(--font-mono)",
            flexShrink: 0, cursor: "pointer", padding: 0,
            transition: "background var(--t-fast) var(--ease)",
          }}
          onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(61,126,245,0.20)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = "var(--ac-d)"; }}
        >
          {user?.avatar_url ? (
            <img src={user.avatar_url} alt="" style={{ width: "100%", height: "100%", borderRadius: "50%", objectFit: "cover" }} />
          ) : initials}
        </button>

        {!collapsed && (
          <button
            type="button"
            onClick={() => navigate("/account")}
            style={{ flex: 1, minWidth: 0, background: "transparent", border: 0, padding: 0, textAlign: "left", cursor: "pointer" }}
          >
            <div style={{
              fontSize: 11, fontWeight: 600, color: "var(--t1)",
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>
              {user?.username || "—"}
            </div>
            <div style={{
              display: "inline-block", marginTop: 2,
              fontSize: 9, padding: "1px 5px", borderRadius: "var(--r-xs)",
              background: "var(--ac-d)",
              border: "1px solid var(--ac-r)",
              color: "var(--ac-h)",
              textTransform: "uppercase", letterSpacing: "0.07em",
              fontWeight: 700,
            }}>
              {user?.role || "user"}
            </div>
          </button>
        )}

        {!collapsed && (
          <button
            onClick={logout}
            title="Log out"
            style={{
              marginLeft: "auto",
              width: 26, height: 26,
              borderRadius: "var(--r-md)",
              background: "transparent", border: "none",
              cursor: "pointer", color: "var(--t4)",
              display: "flex", alignItems: "center", justifyContent: "center",
              transition: "color var(--t-fast) var(--ease), background var(--t-fast) var(--ease)",
              flexShrink: 0,
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = "var(--crit)";
              e.currentTarget.style.background = "var(--crit-d)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = "var(--t4)";
              e.currentTarget.style.background = "transparent";
            }}
          >
            <SignOut size={14} weight="regular" />
          </button>
        )}
      </div>
    </aside>
  );
}

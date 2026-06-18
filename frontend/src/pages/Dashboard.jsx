import { useEffect, useMemo, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, BarChart, Bar, Cell, LabelList,
} from "recharts";
import { ArrowClockwise, ArrowRight, Warning, Pulse } from "@phosphor-icons/react";

import PageHeader from "../components/layout/PageHeader";
import Card, { CardLabel } from "../components/ui/Card";
import KPICard from "../components/KPICard";
import CIARiskPanel from "../components/CIARiskPanel";
import SeverityBadge from "../components/ui/SeverityBadge";
import StatusBadge from "../components/ui/StatusBadge";
import ZoneBadge from "../components/ui/ZoneBadge";
import Table from "../components/ui/Table";
import { IconButton } from "../components/ui/Button";
import ContainmentButton from "../components/ContainmentButton";
import EmptyState from "../components/ui/EmptyState";
import { useDashboard } from "../hooks/useDashboard";
import { useIncidents } from "../hooks/useIncidents";
import { useIntegrations } from "../context/IntegrationContext";
import { chartTooltipStyle } from "../tokens";

// ── Layout constants ─────────────────────────────────────────────────
const SECTION_GAP  = 20;
const CARD_GAP     = 16;
const PAGE_PADDING = 24;
const DASHBOARD_ZONE_LIMIT = 4;
const ZONE_DISPLAY_NAMES = {
  dmz: "DMZ",
  internal: "Internal",
  management: "Management",
  endpoint: "Endpoint",
  cloud: "Cloud",
  vpn: "VPN",
  identity: "Identity",
  firewall: "Firewall",
  web: "Web",
  database: "Database",
  unknown: "Other",
  other: "Other",
};

function SectionLabel({ children }) {
  return (
    <div style={{
      fontSize: 11,
      fontWeight: 600,
      textTransform: "uppercase",
      letterSpacing: "0.09em",
      color: "var(--t4)",
      marginBottom: 10,
      paddingLeft: 2,
    }}>
      {children}
    </div>
  );
}

function fmtAge(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function Onboarding() {
  return (
    <div style={{ padding: "60px 24px" }}>
      <div style={{
        background: "var(--s2)",
        border: "1px solid var(--b1)",
        borderRadius: "var(--r-lg)",
        padding: "52px 48px",
        textAlign: "center",
        maxWidth: 680,
        margin: "0 auto",
        boxShadow: "var(--el-1)",
      }}>
        <div style={{
          width: 48, height: 48,
          borderRadius: "var(--r-md)",
          background: "var(--ac)",
          display: "flex", alignItems: "center", justifyContent: "center",
          margin: "0 auto 16px",
          boxShadow: "var(--el-1)",
        }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
               stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" />
            <line x1="8" y1="12" x2="16" y2="12" />
          </svg>
        </div>
        <div style={{ fontSize: 22, fontWeight: 700, color: "var(--t1)", letterSpacing: "-0.01em" }}>
          Welcome to ZeroTrustX
        </div>
        <div style={{ fontSize: 13, color: "var(--t3)", marginTop: 6 }}>
          Configure your integrations to begin monitoring.
        </div>
        <div style={{ display: "flex", gap: 16, marginTop: 32, flexWrap: "wrap", justifyContent: "center" }}>
          {[
            { name: "Splunk", desc: "Primary SIEM. Sends webhook alerts from all data sources." },
            { name: "pfSense", desc: "Firewall. Enables IP blocking and containment actions." },
          ].map((it) => (
            <Link
              key={it.name}
              to="/settings/integrations"
              style={{
                background: "var(--s1)",
                border: "1px solid var(--b0)",
                borderRadius: "var(--r-md)",
                padding: 24,
                width: 280,
                textAlign: "left",
                textDecoration: "none",
                cursor: "pointer",
                transition: "background var(--t-fast) var(--ease), border-color var(--t-fast) var(--ease)",
                color: "inherit",
                display: "block",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = "var(--b1)";
                e.currentTarget.style.background = "var(--s3)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "var(--b0)";
                e.currentTarget.style.background = "var(--s1)";
              }}
            >
              <div style={{ fontSize: 14, fontWeight: 700, color: "var(--t1)" }}>{it.name}</div>
              <div style={{ fontSize: 12, color: "var(--t3)", marginTop: 6, minHeight: 48 }}>{it.desc}</div>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 6, marginTop: 12, color: "var(--ac-h)", fontSize: 13 }}>
                Configure <ArrowRight size={13} weight="regular" />
              </span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

const ZONE_COLORS = {
  dmz: "#EA580C",
  internal: "#2563EB",
  management: "#7C3AED",
  endpoint: "#0D9488",
  cloud: "#38BDF8",
  vpn: "#A855F7",
  identity: "#F59E0B",
  firewall: "#EF4444",
  web: "#14B8A6",
  database: "#84CC16",
  other: "#64748B",
  unknown: "#475569",
};

function fmtCompact(value) {
  const n = Number(value || 0);
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return String(n);
}

function ReputationPill({ row }) {
  const verdict = row?.overall_verdict || "unknown";
  const color =
    verdict === "malicious" ? "var(--crit)" :
    verdict === "suspicious" ? "var(--med)" :
    verdict === "clean" ? "var(--low)" :
    "var(--t3)";
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 5,
      padding: "2px 6px",
      borderRadius: "var(--r-sm)",
      border: "1px solid var(--b1)",
      background: "var(--s1)",
      color,
      fontSize: 11,
      fontWeight: 700,
      whiteSpace: "nowrap",
    }}>
      {row?.overall_score ?? 0}
      <span style={{ color: "var(--t4)", fontWeight: 600 }}>risk</span>
    </span>
  );
}


export default function Dashboard() {
  const { data, loading, updatedAt, refresh } = useDashboard(15000);
  const { items: recentIncidents } = useIncidents({ per_page: 10, page: 1 });
  const { status } = useIntegrations();
  const navigate = useNavigate();
  const [trendRange, setTrendRange] = useState("24h");
  const [, forceTick] = useState(0);

  useEffect(() => {
    document.title = "Dashboard — ZeroTrustX";
  }, []);

  useEffect(() => {
    const t = setInterval(() => forceTick((v) => v + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const bothUnconfigured =
    status?.splunk && status?.pfsense &&
    !status.splunk.configured && !status.pfsense.configured;

  const open = data?.open_incidents || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  const activeCount = data?.active_containments?.length || 0;

  const trendSeries = useMemo(() => {
    if (!data) return [];
    const list = trendRange === "24h" ? data.trend_24h : data.trend_7d;
    return list.map((p) => ({ t: p.hour || p.date, n: p.count }));
  }, [data, trendRange]);

  const zoneData = useMemo(() => {
    const z = data?.incidents_by_zone || {};
    const sorted = Object.entries(z)
      .map(([zone, count]) => ({ zone, count: Number(count || 0) }))
      .filter((item) => item.count > 0 && item.zone !== "unknown")
      .sort((a, b) => b.count - a.count);

    const topZones = sorted.slice(0, DASHBOARD_ZONE_LIMIT).map((item) => ({
      ...item,
      label: ZONE_DISPLAY_NAMES[item.zone] || item.zone.toUpperCase(),
    }));
    const remainder = sorted.slice(DASHBOARD_ZONE_LIMIT).reduce((sum, item) => sum + item.count, 0);
    const unknownCount = Number(z.unknown || 0);

    if (remainder + unknownCount > 0) {
      topZones.push({
        zone: "other",
        count: remainder + unknownCount,
        label: "Other",
      });
    }

    return topZones;
  }, [data]);

  const updatedSecs = updatedAt ? Math.floor((Date.now() - updatedAt.getTime()) / 1000) : null;
  const updatedStale = updatedSecs !== null && updatedSecs > 60;

  if (bothUnconfigured) {
    return (
      <>
        <PageHeader title="Dashboard" subtitle="Real-time SOC telemetry" />
        <Onboarding />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle="Real-time SOC telemetry"
        actions={
          <>
            <div style={{
              fontSize: 11,
              color: updatedStale ? "var(--med)" : "var(--t3)",
              transition: "color 500ms",
              fontFamily: "var(--font-mono)",
            }}>
              {updatedSecs !== null ? `Updated ${updatedSecs}s ago` : "Updating…"}
            </div>
            <IconButton title="Refresh" onClick={refresh}><ArrowClockwise size={14} weight="regular" /></IconButton>
          </>
        }
      />

      {/* main content */}
      <div style={{ padding: PAGE_PADDING, display: "flex", flexDirection: "column", gap: SECTION_GAP }}>

        {/* KPI row */}
        <div>
          <SectionLabel>Key Metrics</SectionLabel>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: CARD_GAP }}>
            <KPICard
              label="Open Incidents"
              value={open.total}
              sparkData={trendSeries.slice(-12).map((p) => ({ v: p.n }))}
              color="var(--ac-h)"
            />
            <KPICard
              label="Critical / High"
              value={(open.critical || 0) + (open.high || 0)}
              color="var(--crit)"
              delta={6}
            />
            <KPICard
              label="Alerts Today"
              value={data?.alerts_today ?? 0}
              color="var(--high)"
              delta={14}
            />
            <KPICard
              label="Events Ingested"
              value={fmtCompact(data?.events_ingested)}
              color="var(--info)"
              delta={6}
            />
            <KPICard
              label="MTTD (hrs)"
              delta={-11}
              value={data?.mttd_hours != null ? data.mttd_hours.toFixed(1) : "—"}
              color="var(--info)"
            />
            <KPICard
              label="MTTR (hrs)"
              delta={-7}
              value={data?.mttr_hours != null ? data.mttr_hours.toFixed(1) : "—"}
              color="var(--low)"
            />
          </div>
        </div>

        {/* Trend + CIA row */}
        <div>
          <SectionLabel>Threat Intelligence</SectionLabel>
          <div style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: CARD_GAP,
            alignItems: "stretch",
          }}>
            {/* Incident Trend card */}
            <div style={{
              background: "var(--s2)",
              border: "1px solid var(--b1)",
              borderRadius: "var(--r-lg)",
              boxShadow: "var(--el-1)",
              padding: "16px 20px",
              height: "100%",
              boxSizing: "border-box",
              display: "flex",
              flexDirection: "column",
            }}>
              {/* Header */}
              <div style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                minHeight: 28,
                flexShrink: 0,
                marginBottom: 12,
              }}>
                <div>
                  <div style={{
                    fontSize: 10,
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.10em",
                    color: "var(--t3)",
                  }}>
                    Incident Trend
                  </div>
                  <div style={{ fontSize: 10, color: "var(--t4)", marginTop: 2 }}>
                    Incidents over time by severity
                  </div>
                </div>

                {/* Segmented 24H / 7D toggle */}
                <div style={{
                  display: "flex",
                  background: "var(--s1)",
                  border: "1px solid var(--b1)",
                  borderRadius: "var(--r-sm)",
                  overflow: "hidden",
                }}>
                  {["24h", "7d"].map((r) => (
                    <button
                      key={r}
                      onClick={() => setTrendRange(r)}
                      style={{
                        padding: "4px 10px",
                        fontSize: 11,
                        fontWeight: 600,
                        cursor: "pointer",
                        background: trendRange === r ? "var(--ac-d)" : "transparent",
                        border: "none",
                        borderRight: r === "24h" ? "1px solid var(--b1)" : "none",
                        color: trendRange === r ? "var(--ac-h)" : "var(--t3)",
                        transition: "all 120ms ease-out",
                        textTransform: "uppercase",
                        letterSpacing: "0.06em",
                        outline: trendRange === r ? "1px solid var(--ac-r)" : "none",
                        outlineOffset: -1,
                      }}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>

              {/* Chart */}
              <div style={{ flex: 1, minHeight: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendSeries} margin={{ top: 8, right: 16, bottom: 8, left: 8 }}>
                    <defs>
                      <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--ac-h)" stopOpacity={0.12} />
                        <stop offset="100%" stopColor="var(--ac-h)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 5" stroke="var(--b1)" vertical={false} />
                    <XAxis dataKey="t" tick={{ fill: "var(--t3)", fontSize: 11 }} axisLine={false} tickLine={false}
                      tickFormatter={(v) => { if (!v) return ""; return trendRange === "24h" ? v.substring(11, 16) : v; }} />
                    <YAxis tick={{ fill: "var(--t3)", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip {...chartTooltipStyle} />
                    <Area type="monotone" dataKey="n" stroke="var(--ac-h)" strokeOpacity={0.8}
                      strokeWidth={1.5} fill="url(#trendGrad)" name="Incidents"
                      isAnimationActive={true} animationDuration={700} animationEasing="ease-out" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <CIARiskPanel scores={data?.cia_scores || {}} />
          </div>
        </div>

        {/* Attack surface row */}
        <div>
          <SectionLabel>Attack Surface</SectionLabel>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)", gap: CARD_GAP, alignItems: "stretch" }}>
          <Card style={{ minHeight: 354, display: "flex", flexDirection: "column" }}>
            <CardLabel>Top Attacking IPs</CardLabel>
            <Table
              columns={[
                { key: "ip", label: "IP", render: (r) => <span className="mono" style={{ color: "var(--t1)", whiteSpace: "nowrap", minWidth: 110, display: "inline-block" }}>{r.ip}</span> },
                { key: "count", label: "Alerts", render: (r) => <span className="mono">{r.count}</span> },
                { key: "risk", label: "Risk", render: (r) => <ReputationPill row={r} /> },
                { key: "sources", label: "Intel", render: (r) => (
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <span className="mono" style={{ fontSize: 11, color: "var(--t3)" }}>AbuseIPDB {r.abuseipdb_score ?? 0}</span>
                    <span className="mono" style={{ fontSize: 11, color: "var(--t3)" }}>VT {r.virustotal_malicious ?? 0}/{r.virustotal_suspicious ?? 0}</span>
                  </div>
                ) },
                { key: "last_seen", label: "Last Seen", render: (r) => <span style={{ color: "var(--t3)", fontSize: 12 }}>{fmtAge(r.last_seen)}</span> },
                { key: "action", label: "", render: (r) => <ContainmentButton targetIp={r.ip} alias={null} incidentId="standalone" /> },
              ]}
              rows={(data?.top_src_ips || []).slice(0, 5)}
              empty={
                <EmptyState
                  icon={Pulse}
                  title="No attacking IPs recorded"
                  subtitle="No source IPs have triggered multiple alerts in the last 24 hours."
                />
              }
            />
          </Card>

          <Card style={{ minHeight: 354, display: "flex", flexDirection: "column" }}>
            <CardLabel>Incidents by Zone</CardLabel>
            <div style={{ flex: 1, minHeight: 292, marginTop: 4, overflow: "hidden" }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart layout="vertical" data={zoneData} margin={{ top: 10, right: 40, bottom: 8, left: 8 }}>
                  <CartesianGrid strokeDasharray="3 5" stroke="var(--b1)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "var(--t3)", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} domain={[0, (max) => Math.ceil(max * 1.15)]} />
                  <YAxis
                    dataKey="label"
                    type="category"
                    tick={{ fill: "var(--t2)", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    width={86}
                  />
                  <Tooltip {...chartTooltipStyle} />
                  <Bar dataKey="count" barSize={22} radius={[0, 4, 4, 0]} isAnimationActive={true} animationDuration={700} animationEasing="ease-out">
                    {zoneData.map((entry) => (
                      <Cell key={entry.zone} fill={ZONE_COLORS[entry.zone] ?? "#475569"} />
                    ))}
                    <LabelList
                      dataKey="count"
                      position="right"
                      offset={8}
                      style={{ fill: "var(--t2)", fontSize: 11, fontFamily: "var(--font-mono)" }}
                    />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
          </div>
        </div>

        {/* Recent incidents */}
        <div>
          <SectionLabel>Recent Incidents</SectionLabel>
          <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <CardLabel>Recent Incidents</CardLabel>
            <Link to="/incidents" style={{ color: "var(--ac-h)", fontSize: 12, textDecoration: "none", fontWeight: 600 }}>
              View all →
            </Link>
          </div>
          <Table
            columns={[
              { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
              { key: "id", label: "ID", render: (r) => <span className="mono" style={{ color: "var(--t3)", fontSize: 11 }}>#{r.id.slice(0, 8)}</span> },
              { key: "title", label: "Title", render: (r) => (
                <div
                  title={r.title}
                  style={{ color: "var(--t1)", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                >
                  {r.title}
                </div>
              )},
              { key: "asset", label: "Asset", render: (r) => r.asset_hostname
                ? <span className="mono" style={{ fontSize: 12 }}>{r.asset_hostname}</span>
                : <span style={{ color: "var(--t3)" }}>—</span> },
              { key: "zone", label: "Zone", render: (r) => r.asset_zone ? <ZoneBadge zone={r.asset_zone} /> : null },
              { key: "first_seen", label: "Age", render: (r) => <span className="mono" style={{ color: "var(--t3)", fontSize: 12 }}>{fmtAge(r.first_seen)}</span> },
              { key: "status", label: "Status", render: (r) => <StatusBadge status={r.status} /> },
            ]}
            rows={recentIncidents || []}
            onRowClick={(r) => navigate(`/incidents/${r.id}`)}
            empty={
              <EmptyState
                icon={Warning}
                title="No incidents in the last 24h"
                subtitle="Splunk is connected and ingesting data. Incidents will appear here when alerts are correlated."
              />
            }
            rowKey={(r) => r.id}
          />
          </Card>
        </div>

        {/* active containments */}
        {activeCount > 0 && (
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--low)" }} />
              <CardLabel>Active Containments ({activeCount})</CardLabel>
            </div>
            <Table
              columns={[
                { key: "action_type", label: "Type" },
                { key: "target", label: "Target", render: (r) => <span className="mono">{r.target}</span> },
                { key: "incident_id", label: "Incident", render: (r) => r.incident_id
                  ? <Link to={`/incidents/${r.incident_id}`} className="mono"
                          style={{ color: "var(--ac-h)", fontSize: 12, textDecoration: "none" }}>
                      #{r.incident_id.slice(0, 8)}
                    </Link>
                  : "—" },
                { key: "initiated_at", label: "Duration", render: (r) =>
                  <span style={{ color: "var(--t3)", fontSize: 12 }}>{fmtAge(r.initiated_at)}</span> },
              ]}
              rows={data?.active_containments || []}
              empty="No active containments"
            />
          </Card>
        )}
      </div>
    </>
  );
}

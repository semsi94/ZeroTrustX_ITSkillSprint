import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft } from "@phosphor-icons/react";
import PageHeader from "../../components/layout/PageHeader";
import ZoneBadge from "../../components/ui/ZoneBadge";
import SeverityBadge from "../../components/ui/SeverityBadge";
import StatusBadge from "../../components/ui/StatusBadge";
import SourceBadge from "../../components/ui/SourceBadge";
import Table from "../../components/ui/Table";
import Button from "../../components/ui/Button";
import { useAssetQuery } from "../../hooks/queries/useAssetQueries";

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "incidents", label: "Incidents" },
  { key: "alerts", label: "Recent Alerts" },
];

function fmtTs(ts) {
  if (!ts) return "-";
  return new Date(ts).toISOString().replace("T", " ").substring(0, 16);
}

function Field({ label, value, mono }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: "var(--t3)", textTransform: "uppercase",
        letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div className={mono ? "mono" : ""} style={{ fontSize: 13, color: "var(--t1)" }}>{value || "-"}</div>
    </div>
  );
}

export default function AssetDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [tab, setTab] = useState("overview");
  const assetQuery = useAssetQuery(id);

  useEffect(() => {
    document.title = "Asset - ZeroTrustX";
  }, []);

  if (assetQuery.isLoading) {
    return (
      <>
        <PageHeader title="Asset" subtitle="Loading asset..." />
        <div style={{ padding: 24, color: "var(--t3)" }}>Loading...</div>
      </>
    );
  }
  if (assetQuery.error) {
    return (
      <>
        <PageHeader title="Asset" actions={<Button variant="secondary" onClick={() => navigate("/assets")}><ArrowLeft size={14} /> Back</Button>} />
        <div style={{ padding: 24, color: "var(--crit)" }}>{assetQuery.error.message}</div>
      </>
    );
  }

  const data = assetQuery.data;
  if (!data) return null;
  const a = data.asset || data;

  return (
    <>
      <PageHeader
        title={a.hostname || "Asset"}
        subtitle={a.ip}
        actions={
          <Button variant="secondary" onClick={() => navigate("/assets")}>
            <ArrowLeft size={14} /> Back
          </Button>
        }
      />
      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
        <div style={{
          display: "flex", gap: 4,
          borderBottom: "1px solid var(--b0)",
        }}>
          {TABS.map((t) => {
            const active = tab === t.key;
            return (
              <button key={t.key} onClick={() => setTab(t.key)} style={{
                padding: "10px 16px", background: "transparent", border: "none",
                borderBottom: `2px solid ${active ? "var(--ac-h)" : "transparent"}`,
                color: active ? "var(--ac-h)" : "var(--t3)",
                cursor: "pointer", fontSize: 12,
                textTransform: "uppercase", letterSpacing: "0.06em",
                transition: "color var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out)",
              }}>{t.label}</button>
            );
          })}
        </div>

        {tab === "overview" && (
          <div style={{
            background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: 20,
            display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20,
          }}>
            <Field label="Hostname" value={a.hostname} mono />
            <Field label="IP" value={a.ip} mono />
            <Field label="Zone" value={a.zone ? <ZoneBadge zone={a.zone} /> : null} />
            <Field label="Owner" value={a.owner} />
            <Field label="Criticality" value={a.asset_criticality ? `${a.asset_criticality}/5` : "-"} />
            <Field label="Status" value={a.is_placeholder ? "Auto-discovered" : "Managed"} />
            <Field label="Events 24h" value={data.event_count_24h ?? 0} mono />
            <Field label="Events 7d" value={data.event_count_7d ?? 0} mono />
            <Field label="Active Containments" value={(data.active_actions || []).length} mono />
          </div>
        )}

        {tab === "incidents" && (
          <div style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", overflow: "hidden" }}>
            <Table
              columns={[
                { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                { key: "title", label: "Title", render: (r) => <span style={{ color: "#F1F5F9" }}>{r.title || "-"}</span> },
                { key: "status", label: "Status", render: (r) => <StatusBadge status={r.status} /> },
                { key: "first_seen", label: "First Seen",
                  render: (r) => <span className="mono" style={{ fontSize: 12, color: "var(--t3)" }}>{fmtTs(r.first_seen)}</span> },
                { key: "last_seen", label: "Last Seen",
                  render: (r) => <span className="mono" style={{ fontSize: 12, color: "var(--t3)" }}>{fmtTs(r.last_seen)}</span> },
              ]}
              rows={data.incidents || []}
              onRowClick={(r) => navigate(`/incidents/${r.id}`)}
              empty="No incidents for this asset"
              rowKey={(r) => r.id}
              pagination
              pageSize={8}
            />
          </div>
        )}

        {tab === "alerts" && (
          <div style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", overflow: "hidden" }}>
            <Table
              columns={[
                { key: "source_system", label: "Source",
                  render: (r) => <SourceBadge source={r.source_system} short /> },
                { key: "src_ip", label: "Source IP",
                  render: (r) => <span className="mono" style={{ fontSize: 12, whiteSpace: "nowrap", color: "#94A3B8" }}>{r.src_ip || "-"}</span> },
                { key: "dest_ip", label: "Dest IP",
                  render: (r) => <span className="mono" style={{ fontSize: 12, whiteSpace: "nowrap", color: "#94A3B8" }}>{r.dest_ip || "-"}</span> },
                { key: "signature", label: "Signature", render: (r) => r.signature || <span style={{ color: "var(--t3)" }}>-</span> },
                { key: "severity", label: "Severity", render: (r) => <SeverityBadge severity={r.severity || "unknown"} /> },
                { key: "event_time", label: "Time",
                  render: (r) => <span className="mono" style={{ fontSize: 12, color: "var(--t3)" }}>{fmtTs(r.event_time)}</span> },
              ]}
              rows={data.alerts || []}
              empty="No recent alerts"
              rowKey={(r) => r.id}
              pagination
              pageSize={10}
            />
          </div>
        )}
      </div>
    </>
  );
}

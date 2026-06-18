import { useMemo, useState } from "react";
import { Warning as AlertTriangle, CheckCircle as CheckCircle2, ArrowClockwise as RefreshCw, Shield } from "@phosphor-icons/react";
import PageHeader from "../components/layout/PageHeader";
import Card, { CardLabel } from "../components/ui/Card";
import Button from "../components/ui/Button";
import Input, { Textarea } from "../components/ui/Input";
import Table from "../components/ui/Table";
import StatusBadge from "../components/ui/StatusBadge";
import EmptyState from "../components/ui/EmptyState";
import { useAuth } from "../context/AuthContext";
import {
  useBlockedIps,
  useBlockIp,
  useCheckIp,
  useContainmentHistory,
  useFirewallStatus,
  useUnblockIp,
} from "../hooks/queries/useResponseQueries";

function fmtTs(value) {
  if (!value) return "-";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toISOString().replace("T", " ").slice(0, 19);
}

function Banner({ tone = "info", children }) {
  const isError = tone === "error";
  const isSuccess = tone === "success";
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "10px 12px",
      borderRadius: 8,
      background: isError ? "rgba(220,38,38,0.10)" : isSuccess ? "rgba(22,163,74,0.10)" : "rgba(37,99,235,0.08)",
      border: `1px solid ${isError ? "rgba(220,38,38,0.35)" : isSuccess ? "rgba(22,163,74,0.30)" : "rgba(37,99,235,0.25)"}`,
      color: isError ? "#FCA5A5" : "var(--t2)",
      fontSize: 13,
    }}>
      {children}
    </div>
  );
}

function ActionForm({ title, button, disabled, onSubmit, requireReason = true }) {
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [incidentId, setIncidentId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function submit() {
    setError(null);
    if (!ip.trim()) {
      setError("IP address is required.");
      return;
    }
    if (requireReason && !reason.trim()) {
      setError("Reason is required for auditable firewall changes.");
      return;
    }
    setLoading(true);
    try {
      await onSubmit({ ip: ip.trim(), reason: reason.trim(), incident_id: incidentId.trim() || null });
      setIp("");
      setReason("");
      setIncidentId("");
    } catch (e) {
      setError(e?.message || "Firewall action failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section style={{ border: "1px solid var(--b1)", background: "var(--s1)", borderRadius: 8, padding: 12 }}>
      <div style={{ color: "var(--t1)", fontWeight: 700, marginBottom: 10 }}>{title}</div>
      {error && <div style={{ marginBottom: 10 }}><Banner tone="error"><AlertTriangle size={14} /> {error}</Banner></div>}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        <label style={fieldStyle}>IP address<Input value={ip} onChange={(e) => setIp(e.target.value)} disabled={disabled || loading} placeholder="203.0.113.45" /></label>
        <label style={fieldStyle}>Incident ID<Input value={incidentId} onChange={(e) => setIncidentId(e.target.value)} disabled={disabled || loading} placeholder="Optional" /></label>
      </div>
      {requireReason && (
        <label style={{ ...fieldStyle, marginTop: 10 }}>Reason<Textarea value={reason} onChange={(e) => setReason(e.target.value)} disabled={disabled || loading} placeholder="Why is this firewall action required?" style={{ minHeight: 74 }} /></label>
      )}
      <Button variant="secondary" onClick={submit} disabled={disabled || loading} style={{ marginTop: 10 }}>
        {loading ? "Working..." : button}
      </Button>
    </section>
  );
}

export default function FirewallResponse() {
  const { user } = useAuth();
  const [toast, setToast] = useState(null);
  const [checkResult, setCheckResult] = useState(null);
  const statusQuery = useFirewallStatus();
  const blockedQuery = useBlockedIps();
  const actionsQuery = useContainmentHistory();
  const blockMutation = useBlockIp();
  const unblockMutation = useUnblockIp();
  const checkMutation = useCheckIp();

  const canContain = useMemo(() => !["viewer", "degraded"].includes(user?.role), [user]);
  const status = statusQuery.data || {};
  const blocked = Array.isArray(blockedQuery.data?.blocked_ips) ? blockedQuery.data.blocked_ips : [];
  const actions = Array.isArray(actionsQuery.data?.actions) ? actionsQuery.data.actions : [];
  const loading = statusQuery.isLoading || blockedQuery.isLoading || actionsQuery.isLoading;
  const error = statusQuery.error?.message || blockedQuery.error?.message || actionsQuery.error?.message || null;
  const configured = Boolean(status?.configured);
  const connected = Boolean(status?.connected);

  function showToast(message) {
    setToast(message);
    setTimeout(() => setToast(null), 2600);
  }

  function refresh() {
    statusQuery.refetch();
    blockedQuery.refetch();
    actionsQuery.refetch();
  }

  async function blockIp(payload) {
    const data = await blockMutation.mutateAsync(payload);
    if (data.error) throw new Error(data.error);
    showToast(`Blocked ${payload.ip}`);
  }

  async function unblockIp(payload) {
    const data = await unblockMutation.mutateAsync(payload);
    if (data.error) throw new Error(data.error);
    showToast(`Unblocked ${payload.ip}`);
  }

  async function checkIp(payload) {
    const data = await checkMutation.mutateAsync(payload);
    if (data.error) throw new Error(data.error);
    setCheckResult(data);
    showToast(`Checked ${payload.ip}`);
  }

  return (
    <>
      <PageHeader
        title="Firewall Response"
        subtitle="Audit and manage pfSense containment actions"
        actions={<Button variant="secondary" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</Button>}
      />
      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 16 }}>
        {toast && <Banner tone="success"><CheckCircle2 size={15} /> {toast}</Banner>}
        {error && <Banner tone="error"><AlertTriangle size={15} /> {error}</Banner>}
        {!canContain && <Banner><Shield size={15} /> Viewer role can inspect firewall response history but cannot run containment actions.</Banner>}

        <Card>
          <CardLabel>pfSense Status</CardLabel>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10 }}>
            <InfoBox label="Configuration" value={configured ? "Configured" : "Not configured"} />
            <InfoBox label="Connection" value={connected ? "Connected" : status?.status || "Unavailable"} />
            <InfoBox label="Block alias" value={status?.alias || "-"} />
            <InfoBox label="Message" value={loading ? "Loading..." : status?.message || status?.error || "-"} />
          </div>
          {!configured && (
            <div style={{ marginTop: 12 }}>
              <Banner>pfSense is not configured. Add host, credentials, and block alias in Settings.</Banner>
            </div>
          )}
        </Card>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 16 }}>
          <ActionForm title="Block IP" button="Block IP" disabled={!canContain || !configured} onSubmit={blockIp} />
          <ActionForm title="Unblock IP" button="Unblock IP" disabled={!canContain || !configured} onSubmit={unblockIp} />
          <ActionForm title="Check IP Status" button="Check status" disabled={!canContain || !configured} onSubmit={checkIp} requireReason={false} />
        </div>

        {checkResult && (
          <Card>
            <CardLabel>Last Status Check</CardLabel>
            <div style={{ color: "var(--t2)", fontSize: 13 }}>
              <span className="mono">{checkResult.ip}</span> is {checkResult.blocked ? "currently in" : "not in"} alias <span className="mono">{checkResult.alias}</span>.
            </div>
          </Card>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "320px minmax(0, 1fr)", gap: 16 }}>
          <Card>
            <CardLabel>Blocked IPs</CardLabel>
            {blockedQuery.isLoading ? (
              <div className="skeleton" style={{ height: 120 }} />
            ) : blocked.length ? (
              <div className="scrollbar-thin" style={{ maxHeight: 360, overflow: "auto", display: "grid", gap: 6 }}>
                {blocked.map((ip) => (
                  <div key={ip} className="mono" style={{ padding: "7px 9px", border: "1px solid var(--b1)", background: "var(--s1)", borderRadius: 6, color: "var(--t2)" }}>{ip}</div>
                ))}
              </div>
            ) : (
              <EmptyState title="No blocked IPs returned" subtitle="The configured pfSense alias is empty or not readable." />
            )}
          </Card>

          <Card>
            <CardLabel>Recent Containment Actions</CardLabel>
            <Table
              columns={[
                { key: "requested_at", label: "Requested", render: (r) => <span className="mono">{fmtTs(r.requested_at)}</span> },
                { key: "action_type", label: "Action", render: (r) => String(r.action_type || "-").replace(/_/g, " ") },
                { key: "target_ip", label: "Target", render: (r) => <span className="mono">{r.target_ip || "-"}</span> },
                { key: "requested_by", label: "By", render: (r) => r.requested_by || "-" },
                { key: "status", label: "Status", render: (r) => <StatusBadge status={r.status || "unknown"} /> },
                { key: "reason", label: "Reason", render: (r) => r.reason || "-" },
              ]}
              rows={actions}
              rowKey={(r) => r.id}
              empty="No containment actions recorded"
              loading={actionsQuery.isLoading}
              error={actionsQuery.error?.message}
              pagination
              pageSize={10}
            />
          </Card>
        </div>
      </div>
    </>
  );
}

function InfoBox({ label, value }) {
  return (
    <div style={{ padding: 10, border: "1px solid var(--b1)", background: "var(--s1)", borderRadius: 8, minWidth: 0 }}>
      <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div style={{ color: "var(--t1)", fontSize: 13, marginTop: 5, overflow: "hidden", textOverflow: "ellipsis" }} title={String(value || "")}>{value || "-"}</div>
    </div>
  );
}

const fieldStyle = {
  display: "flex",
  flexDirection: "column",
  gap: 5,
  color: "var(--t3)",
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  minWidth: 0,
};

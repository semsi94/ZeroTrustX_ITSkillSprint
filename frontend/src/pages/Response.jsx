import { useEffect, useState } from "react";
import {
  Warning as AlertTriangle,
  CheckCircle as CheckCircle2,
  CaretDown as ChevronDown,
  CaretRight as ChevronRight,
  Clock,
  ArrowClockwise as RefreshCw,
  Shield,
  XCircle,
} from "@phosphor-icons/react";
import PageHeader from "../components/layout/PageHeader";
import Button from "../components/ui/Button";
import Input, { Textarea } from "../components/ui/Input";
import AppSelect from "../components/ui/AppSelect";
import EmptyState from "../components/ui/EmptyState";
import Table from "../components/ui/Table";
import { getApiError } from "../api/client";
import { useAuth } from "../context/AuthContext";
import { useContainmentHistory, useFirewallAction, useFirewallStatus } from "../hooks/queries/useResponseQueries";

const ACTIONS = [
  { value: "block_ip", label: "Block IP" },
  { value: "unblock_ip", label: "Unblock IP" },
  { value: "check_status", label: "Check IP Status" },
];

const ACTION_STATUS_STYLES = {
  pending: { color: "#CA8A04", bg: "rgba(202,138,4,0.12)", border: "rgba(202,138,4,0.30)" },
  pending_approval: { color: "#EA580C", bg: "rgba(234,88,12,0.12)", border: "rgba(234,88,12,0.30)" },
  executed: { color: "#16A34A", bg: "rgba(22,163,74,0.12)", border: "rgba(22,163,74,0.30)" },
  failed: { color: "#DC2626", bg: "rgba(220,38,38,0.12)", border: "rgba(220,38,38,0.30)" },
  reverted: { color: "#6366F1", bg: "rgba(99,102,241,0.12)", border: "rgba(99,102,241,0.30)" },
};

function fmtTs(value) {
  if (!value) return "-";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toISOString().replace("T", " ").slice(0, 19);
}

function ActionStatusBadge({ status }) {
  const s = (status || "").toLowerCase();
  const style = ACTION_STATUS_STYLES[s] || { color: "#64748B", bg: "rgba(100,116,139,0.10)", border: "rgba(100,116,139,0.25)" };
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 8px", borderRadius: 4,
      background: style.bg, border: `1px solid ${style.border}`,
      color: style.color, fontSize: 11,
      fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em",
      whiteSpace: "nowrap",
    }}>
      {s.replace(/_/g, " ") || "unknown"}
    </span>
  );
}

function PendingApprovalCard({ action }) {
  return (
    <div style={{
      background: "rgba(202,138,4,0.06)",
      border: "1px solid rgba(202,138,4,0.25)",
      borderLeft: "3px solid #CA8A04",
      borderRadius: 8,
      padding: "14px 16px",
      display: "flex",
      alignItems: "center",
      gap: 16,
    }}>
      <div style={{
        width: 8, height: 8,
        borderRadius: "50%",
        background: "#CA8A04",
        flexShrink: 0,
        animation: "pendingPulse 1.6s ease-in-out infinite",
      }} />

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--t1)" }}>
          {String(action.action_type || "-").replace(/_/g, " ")}
        </div>
        <div style={{ fontSize: 12, color: "var(--t2)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
          Target: {action.target_ip || "-"}
        </div>
        <div style={{ fontSize: 11, color: "var(--t3)", marginTop: 3 }}>
          Requested by {action.requested_by || "-"} | {action.requested_at ? new Date(action.requested_at).toLocaleTimeString() : "-"}
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 5, minWidth: 0 }}>
      <span style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</span>
      {children}
    </label>
  );
}

function Banner({ tone = "info", children }) {
  const isError = tone === "error";
  const Icon = isError ? XCircle : CheckCircle2;
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "10px 14px",
      borderRadius: "var(--r-md)",
      border: `1px solid ${isError ? "rgba(207,74,74,0.28)" : "rgba(37,99,235,0.22)"}`,
      background: isError ? "var(--crit-d)" : "rgba(37,99,235,0.07)",
      color: isError ? "var(--crit)" : "var(--t2)",
      fontSize: 12,
      minWidth: 0,
    }}>
      <Icon size={15} />
      <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{children}</span>
    </div>
  );
}

function Collapsible({ title, subtitle, open, onToggle, children }) {
  return (
    <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", overflow: "hidden", minWidth: 0 }}>
      <button
        type="button"
        onClick={onToggle}
        style={{
          width: "100%",
          border: "none",
          background: "transparent",
          color: "var(--t1)",
          padding: 14,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span style={{ minWidth: 0 }}>
          <span style={{ display: "block", fontWeight: 700 }}>{title}</span>
          {subtitle && <span style={{ display: "block", color: "var(--t3)", fontSize: 12, marginTop: 2 }}>{subtitle}</span>}
        </span>
        {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
      </button>
      {open && <div style={{ padding: "0 14px 14px" }}>{children}</div>}
    </section>
  );
}

export default function Response() {
  const { user } = useAuth();
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [action, setAction] = useState("block_ip");
  const [targetIp, setTargetIp] = useState("");
  const [reason, setReason] = useState("");
  const [incidentId, setIncidentId] = useState("");
  const [ticketId, setTicketId] = useState("");
  const [notes, setNotes] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(true);
  const statusQuery = useFirewallStatus();
  const actionsQuery = useContainmentHistory();
  const actionMutation = useFirewallAction();

  const status = statusQuery.data || null;
  const actionsData = actionsQuery.data || {};
  const actions = Array.isArray(actionsData.actions) ? actionsData.actions : [];
  const loading = statusQuery.isLoading || actionsQuery.isLoading;
  const submitting = actionMutation.isPending;
  const loadError = statusQuery.error?.message || actionsQuery.error?.message || null;

  const canRespond = user && !["viewer", "degraded"].includes(user.role);
  const needsReason = action === "block_ip" || action === "unblock_ip";
  const buttonLabel = ACTIONS.find((item) => item.value === action)?.label || "Run action";

  useEffect(() => {
    document.title = "Response - ZeroTrustX";
  }, []);

  async function submitAction() {
    setError(null);
    setResult(null);
    const ip = targetIp.trim();
    if (!ip) {
      setError("Target IP is required.");
      return;
    }
    if (needsReason && !reason.trim()) {
      setError("Reason is required for block and unblock actions.");
      return;
    }
    try {
      const data = await actionMutation.mutateAsync({
        action,
        target_ip: ip,
        reason: reason.trim(),
        incident_id: incidentId.trim() || null,
        ticket_id: ticketId.trim() || null,
        notes: notes.trim() || null,
      });
      setResult(data);
    } catch (e) {
      setError(getApiError(e, "Firewall action failed"));
    }
  }

  const pendingApprovalRows = actions.filter((row) => row.status === "pending_approval");

  return (
    <>
      <PageHeader title="Response" subtitle="Execute and track containment actions" />
      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 18, minWidth: 0, maxWidth: "100%" }}>
        {error && <Banner tone="error">{error}</Banner>}
        {!error && loadError && <Banner tone="error">{loadError}</Banner>}

        {!status?.configured && !loading && (
          <Banner tone="error">pfSense is not configured. {user?.role === "admin" ? "Configure it in Settings before running containment actions." : "Ask an admin to configure it in Settings."}</Banner>
        )}
        {!canRespond && (
          <Banner tone="error">Viewer role can inspect response history but cannot run containment actions.</Banner>
        )}

        <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: 16, display: "grid", gap: 14, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Shield size={18} color="var(--ac-h)" />
            <div>
              <div style={{ color: "var(--t1)", fontWeight: 800 }}>Response Action</div>
              <div style={{ color: "var(--t3)", fontSize: 12 }}>Select one operation, target an IP, and record the reason for audit.</div>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, minWidth: 0 }}>
            <Field label="Action">
              <AppSelect value={action} onChange={setAction} options={ACTIONS} disabled={!canRespond || submitting} />
            </Field>
            <Field label="Target IP">
              <Input value={targetIp} onChange={(e) => setTargetIp(e.target.value)} placeholder="192.168.180.50" disabled={!canRespond || submitting} />
            </Field>
          </div>

          {needsReason && (
            <Field label="Reason">
              <Textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why this containment action is needed"
                style={{ minHeight: 82 }}
                disabled={!canRespond || submitting}
              />
            </Field>
          )}

          <Collapsible
            title="Advanced Options"
            subtitle="Optional incident link and analyst notes"
            open={advancedOpen}
            onToggle={() => setAdvancedOpen((value) => !value)}
          >
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, minWidth: 0 }}>
              <Field label="Incident ID">
                <Input value={incidentId} onChange={(e) => setIncidentId(e.target.value)} placeholder="Optional UUID" disabled={!canRespond || submitting} />
              </Field>
              <Field label="Ticket ID">
                <Input value={ticketId} onChange={(e) => setTicketId(e.target.value)} placeholder="Optional UUID" disabled={!canRespond || submitting} />
              </Field>
              <Field label="Notes">
                <Input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Optional context" disabled={!canRespond || submitting} />
              </Field>
            </div>
          </Collapsible>

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
            <Button
              variant="primary"
              onClick={submitAction}
              disabled={!canRespond || submitting || !targetIp.trim() || (needsReason && !reason.trim())}
            >
              {submitting ? <RefreshCw size={14} /> : null}
              {submitting ? "Running..." : buttonLabel}
            </Button>
            {loading && <span style={{ color: "var(--t3)", fontSize: 12 }}>Loading firewall state...</span>}
          </div>

          {result && (
            <div style={{
              border: `1px solid ${result.success ? "rgba(22,163,74,0.35)" : "rgba(220,38,38,0.35)"}`,
              background: result.success ? "rgba(22,163,74,0.10)" : "rgba(220,38,38,0.10)",
              borderRadius: 8,
              padding: 12,
              display: "grid",
              gap: 6,
              color: result.success ? "#BBF7D0" : "#FCA5A5",
              fontSize: 13,
              minWidth: 0,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 800 }}>
                {result.success ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
                {result.success ? "Action completed" : "Action failed"}
              </div>
              <div>Target: <span className="mono">{result.target_ip || targetIp}</span></div>
              <div>Status: {result.status || "-"}</div>
              <div style={{ overflowWrap: "anywhere" }}>{result.error || result.message || "-"}</div>
              <div style={{ color: "var(--t3)" }}>Recorded: {fmtTs(result.audit?.requested_at || new Date().toISOString())}</div>
            </div>
          )}
        </section>

        <Collapsible
          title="Recent Containment Actions"
          subtitle={`${actions.length} audit record${actions.length === 1 ? "" : "s"}`}
          open={historyOpen}
          onToggle={() => setHistoryOpen((value) => !value)}
        >
          {actions.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {pendingApprovalRows.map((row, idx) => (
                <PendingApprovalCard key={row.id || idx} action={row} />
              ))}

              <Table
                columns={[
                  { key: "requested_at", label: "Time", render: (r) => <span className="mono">{fmtTs(r.requested_at)}</span> },
                  { key: "action_type", label: "Action", render: (r) => String(r.action_type || "-").replace(/_/g, " ") },
                  { key: "target_ip", label: "Target IP", render: (r) => <span className="mono">{r.target_ip || "-"}</span> },
                  { key: "status", label: "Status", render: (r) => <ActionStatusBadge status={r.status} /> },
                  { key: "reason", label: "Reason", render: (r) => <span title={r.reason || ""} style={{ display: "block", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.reason || "-"}</span> },
                  { key: "requested_by", label: "User", render: (r) => r.requested_by || "-" },
                  { key: "incident_id", label: "Incident", render: (r) => <span className="mono">{r.incident_id ? r.incident_id.slice(0, 8) : "-"}</span> },
                  { key: "ticket_id", label: "Ticket", render: (r) => <span className="mono">{r.ticket_id ? r.ticket_id.slice(0, 8) : "-"}</span> },
                  { key: "firewall", label: "Firewall", render: (r) => r.firewall || "pfSense" },
                ]}
                rows={actions}
                rowKey={(r) => r.id}
                empty="No containment actions recorded"
                loading={actionsQuery.isLoading}
                error={actionsQuery.error?.message || null}
                pagination
                pageSize={10}
              />
            </div>
          ) : (
            <EmptyState
              icon={Clock}
              title="No containment actions recorded"
              subtitle="Block, unblock, and status checks will appear here with the requested user, reason, and result."
            />
          )}
        </Collapsible>
      </div>
    </>
  );
}

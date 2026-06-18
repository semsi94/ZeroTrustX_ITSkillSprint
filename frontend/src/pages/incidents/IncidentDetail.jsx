import { Component, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, CheckCircle as CheckCircle2, Download, ArrowSquareOut as ExternalLink, Shield, Trash as Trash2, XCircle } from "@phosphor-icons/react";
import PageHeader from "../../components/layout/PageHeader";
import SeverityBadge from "../../components/ui/SeverityBadge";
import StatusBadge from "../../components/ui/StatusBadge";
import Card, { CardLabel } from "../../components/ui/Card";
import Button from "../../components/ui/Button";
import Table from "../../components/ui/Table";
import AppSelect from "../../components/ui/AppSelect";
import Modal from "../../components/ui/Modal";
import EmptyState from "../../components/ui/EmptyState";
import ContainmentButton from "../../components/ContainmentButton";
import IncidentMitreWorkspace, { IncidentMitreSummaryCard } from "../../components/mitre/IncidentMitreWorkspace";
import IpReputationBadge from "../../components/reputation/IpReputationBadge";
import Input, { Textarea } from "../../components/ui/Input";
import { useAuth } from "../../context/AuthContext";
import {
  useBulkAddEvidence,
  useDeleteIncident,
  useDownloadIncidentPdf,
  useIncident,
  useAddIncidentComment,
  useIncidentActivity,
  useIncidentComments,
  useIncidentWorkflow,
  useTriggeredAlertDetail,
  useUpdateIncident,
  useUpdateIncidentWorkflow,
} from "../../hooks/queries/useIncidentQueries";
import { useIncidentIpReputation } from "../../hooks/queries/useReputationQueries";

const STATUSES = [
  "draft",
  "pending_evidence",
  "pending_approval",
  "new",
  "triage",
  "investigating",
  "contained",
  "monitoring",
  "resolved",
  "closed",
  "rejected",
].map((value) => ({ value, label: value.replace(/_/g, " ") }));

const VERDICTS = [
  ["undecided", "Undecided"],
  ["true_positive", "True Positive"],
  ["false_positive", "False Positive"],
  ["benign_positive", "Benign Positive"],
  ["duplicate", "Duplicate"],
  ["needs_more_evidence", "Needs More Evidence"],
].map(([value, label]) => ({ value, label }));

const WORKFLOW_STATUSES = [
  ["open", "Open"],
  ["assigned", "Assigned"],
  ["in_progress", "In Progress"],
  ["waiting", "Waiting"],
  ["escalated", "Escalated"],
  ["resolved", "Resolved"],
  ["closed", "Closed"],
  ["cancelled", "Cancelled"],
].map(([value, label]) => ({ value, label }));

const PRIORITIES = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
].map(([value, label]) => ({ value, label }));

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function fmtTs(value) {
  if (!value) return "-";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toISOString().replace("T", " ").slice(0, 19);
}

function toLocalDateInput(value) {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function text(value) {
  if (value === null || value === undefined || value === "") return "-";
  return String(value);
}

function eventMessage(event) {
  return event?.message || event?.signature || event?.action || JSON.stringify(event?.raw || event || {}).slice(0, 140);
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean).map(String)));
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeObservableGroups(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    users: asArray(source.users),
    hosts: asArray(source.hosts),
    source_ips: asArray(source.source_ips),
    destination_ips: asArray(source.destination_ips),
    urls: asArray(source.urls),
    domains: asArray(source.domains),
    hashes: asArray(source.hashes),
    files: asArray(source.files),
  };
}

function isValidIncidentId(value) {
  return typeof value === "string" && UUID_RE.test(value);
}

class IncidentDetailErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error) {
    if (import.meta.env.DEV) {
      console.error("Incident detail failed to render", error);
    }
  }

  componentDidUpdate(prevProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.hasError) {
      this.setState({ hasError: false });
    }
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback ?? null;
    }
    return this.props.children;
  }
}

function Banner({ tone = "info", children }) {
  const isError = tone === "error";
  return (
    <div style={{
      display: "flex",
      gap: 8,
      alignItems: "center",
      padding: "10px 14px",
      borderRadius: "var(--r-md)",
      border: `1px solid ${isError ? "rgba(207,74,74,0.28)" : "rgba(37,99,235,0.22)"}`,
      background: isError ? "var(--crit-d)" : "rgba(37,99,235,0.07)",
      color: isError ? "var(--crit)" : "var(--t2)",
      fontSize: 12,
    }}>
      {children}
    </div>
  );
}

function IncidentPageState({
  title,
  message,
  tone = "info",
  actionLabel = "Back to incidents",
  onAction,
  onSecondaryAction,
  secondaryLabel = "Retry",
}) {
  return (
    <>
      <PageHeader
        title="Incident"
        actions={onAction ? <Button variant="secondary" onClick={onAction}><ArrowLeft size={14} /> {actionLabel}</Button> : null}
      />
      <div style={{ padding: 24, display: "grid", gap: 14 }}>
        <Banner tone={tone}>
          <XCircle size={15} /> <strong>{title}</strong>{message ? <span style={{ marginLeft: 6 }}>{message}</span> : null}
        </Banner>
        {onSecondaryAction ? (
          <div>
            <Button variant="secondary" onClick={onSecondaryAction}>{secondaryLabel}</Button>
          </div>
        ) : null}
      </div>
    </>
  );
}

function InfoGrid({ items }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 10 }}>
      {items.map(([label, value]) => (
        <div key={label} style={{
          padding: 10,
          borderRadius: 8,
          border: "1px solid var(--b1)",
          background: "var(--s1)",
          minWidth: 0,
        }}>
          <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
          <div style={{ color: "var(--t1)", fontSize: 13, marginTop: 5, overflow: "hidden", textOverflow: "ellipsis" }} title={String(value || "")}>
            {text(value)}
          </div>
        </div>
      ))}
    </div>
  );
}

function EventTable({ events, onView, reputationByIp, canRefreshReputation }) {
  function IpCell({ ip }) {
    if (!ip) return <span className="mono">-</span>;
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
        <span className="mono">{ip}</span>
        <IpReputationBadge ip={ip} reputation={reputationByIp?.get?.(ip)} canRefresh={canRefreshReputation} />
      </span>
    );
  }
  return (
    <Table
      columns={[
        { key: "time", label: "Time", render: (r) => <span className="mono">{fmtTs(r.time || r._time || r.event_time)}</span> },
        { key: "severity", label: "Severity", render: (r) => <SeverityBadge severity={r.severity || r.level || "unknown"} /> },
        { key: "source_ip", label: "Source IP", render: (r) => <IpCell ip={r.source_ip} /> },
        { key: "destination_ip", label: "Destination IP", render: (r) => <IpCell ip={r.destination_ip} /> },
        { key: "user", label: "User", render: (r) => text(r.user || r.email || r.user_email) },
        { key: "host", label: "Host", render: (r) => text(r.host) },
        { key: "action", label: "Action", render: (r) => text(r.action) },
        { key: "category", label: "Category", render: (r) => text(r.category) },
        { key: "status_code", label: "Status", render: (r) => text(r.status_code) },
        { key: "message", label: "Message", render: (r) => (
          <span title={eventMessage(r)} style={{ display: "block", maxWidth: 360, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {eventMessage(r)}
          </span>
        ) },
      ]}
      rows={Array.isArray(events) ? events : []}
      rowKey={(r, i) => r.event_hash || r.id || `${r.time || r._time || r.event_time || "event"}-${i}`}
      onRowClick={onView}
      empty="No logs attached"
      pagination
      pageSize={8}
    />
  );
}

function EvidenceTimeline({ events, selectedId, onSelect }) {
  const rows = [...(Array.isArray(events) ? events : [])].sort((a, b) => {
    const at = new Date(a.event_time || a.time || a._time || a.added_at || 0).getTime();
    const bt = new Date(b.event_time || b.time || b._time || b.added_at || 0).getTime();
    return (Number.isNaN(at) ? 0 : at) - (Number.isNaN(bt) ? 0 : bt);
  });

  if (!rows.length) {
    return <EmptyState title="No evidence has been attached yet" subtitle="Add Splunk logs, alert results, or investigation events to build the incident timeline." />;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {rows.map((event, idx) => {
        const id = event.event_hash || event.id || `${event.event_time || event.time || idx}`;
        const active = selectedId === id;
        return (
          <button
            key={id}
            type="button"
            onClick={() => onSelect?.(event, id)}
            style={{
              display: "grid",
              gridTemplateColumns: "120px 18px minmax(0, 1fr)",
              gap: 10,
              alignItems: "start",
              width: "100%",
              textAlign: "left",
              border: `1px solid ${active ? "var(--ac-r)" : "var(--b0)"}`,
              background: active ? "var(--ac-d)" : "var(--s1)",
              borderRadius: 8,
              padding: 10,
              cursor: "pointer",
              color: "var(--t2)",
            }}
          >
            <span className="mono" style={{ color: "var(--t3)", fontSize: 11 }}>{fmtTs(event.event_time || event.time || event._time)}</span>
            <span style={{
              width: 10,
              height: 10,
              marginTop: 3,
              borderRadius: "50%",
              background: active ? "var(--ac-h)" : "var(--b1)",
              border: "1px solid var(--b1)",
            }} />
            <span style={{ minWidth: 0 }}>
              <span style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <SeverityBadge severity={event.severity || event.level || "unknown"} />
                <span style={{ color: "var(--t1)", fontWeight: 700 }}>{eventMessage(event)}</span>
              </span>
              <span style={{ display: "flex", gap: 10, flexWrap: "wrap", color: "var(--t3)", fontSize: 12, marginTop: 6 }}>
                <span className="mono">{text(event.source_ip)} -&gt; {text(event.destination_ip)}</span>
                <span>{text(event.user || event.email || event.user_email)}</span>
                <span>{text(event.host)}</span>
                <span>{text(event.action)}</span>
                <span>{text(event.category)}</span>
                <span>{text(event.source || event.event_source || "Splunk")}</span>
              </span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

export default function IncidentDetail() {
  const { id } = useParams();
  const navigate = useNavigate();

  if (!id || !isValidIncidentId(id)) {
    return (
      <IncidentPageState
        title="Invalid incident ID."
        message="The incident link is malformed or incomplete."
        tone="error"
        onAction={() => navigate("/incidents")}
      />
    );
  }

  return (
    <IncidentDetailErrorBoundary
      resetKey={id}
      fallback={(
        <IncidentPageState
          title="Incident detail failed to render."
          message="A component on this page threw an error. You can retry or go back to the incident queue."
          tone="error"
          onAction={() => navigate("/incidents")}
          onSecondaryAction={() => window.location.reload()}
          secondaryLabel="Retry"
        />
      )}
    >
      <IncidentDetailContent id={id} />
    </IncidentDetailErrorBoundary>
  );
}

function IncidentDetailContent({ id }) {
  const { user } = useAuth();
  const navigate = useNavigate();
  const incidentQuery = useIncident(id);
  const workflowQuery = useIncidentWorkflow(id);
  const commentsQuery = useIncidentComments(id);
  const activityQuery = useIncidentActivity(id);
  const reputationQuery = useIncidentIpReputation(id);
  const updateIncidentMutation = useUpdateIncident();
  const updateWorkflowMutation = useUpdateIncidentWorkflow();
  const addCommentMutation = useAddIncidentComment();
  const bulkAddEvidenceMutation = useBulkAddEvidence();
  const deleteIncidentMutation = useDeleteIncident();
  const downloadPdfMutation = useDownloadIncidentPdf();
  const [notes, setNotes] = useState("");
  const [workflow, setWorkflow] = useState({});
  const [comment, setComment] = useState("");
  const [verdict, setVerdict] = useState("undecided");
  const [verdictReason, setVerdictReason] = useState("");
  const [mitreOpen, setMitreOpen] = useState(false);
  const [rawView, setRawView] = useState(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState(null);
  const [toast, setToast] = useState(null);
  const [actionError, setActionError] = useState(null);

  const incident = incidentQuery.data?.incident || incidentQuery.data || null;
  const isSplunkCandidate = incident?.source === "splunk" || incident?.detection_source === "splunk_alert";
  const triggeredQuery = useTriggeredAlertDetail(id, { enabled: Boolean(id) && isSplunkCandidate });
  const triggered = triggeredQuery.data || null;
  const triggeringEvents = asArray(triggered?.triggeringEvents);
  const evidence = asArray(incident?.evidence);
  const containmentActions = asArray(incident?.containment_actions ?? incident?.response_actions);
  const workflowData = workflowQuery.data?.workflow || incident?.workflow || {};
  const comments = asArray(commentsQuery.data?.comments ?? incident?.comments);
  const activity = asArray(activityQuery.data?.activity ?? incident?.activity);
  const observables = normalizeObservableGroups(incident?.observables);
  const canWrite = !["viewer", "degraded"].includes(user?.role);
  const reputationByIp = useMemo(() => {
    const map = new Map();
    (reputationQuery.data?.reputations || []).forEach((item) => map.set(item.ip_address, item));
    return map;
  }, [reputationQuery.data]);
  const canApprove = user?.role === "admin";
  const canDelete = user?.role === "admin";
  const canExport = user?.role !== "viewer";
  const saving = updateIncidentMutation.isPending || updateWorkflowMutation.isPending || bulkAddEvidenceMutation.isPending || deleteIncidentMutation.isPending;

  useEffect(() => {
    document.title = "Incident - ZeroTrustX";
  }, []);

  useEffect(() => {
    if (!incident) return;
    setNotes(incident.notes || incident.description || "");
    setWorkflow({
      queue: workflowData.queue || incident.queue || "SOC",
      owner: workflowData.assignee || incident.owner || "",
      priority: workflowData.priority || incident.priority || incident.severity || "medium",
      workflow_status: workflowData.workflow_status || incident.workflow_status || "open",
      sla_due_at: toLocalDateInput(workflowData.sla_due_at || incident.sla_due_at),
      first_ack_due_at: toLocalDateInput(workflowData.first_ack_due_at || incident.first_ack_due_at),
      resolve_due_at: toLocalDateInput(workflowData.resolve_due_at || incident.resolve_due_at),
      escalation_level: String(workflowData.escalation_level ?? incident.escalation_level ?? 0),
      requested_action: workflowData.requested_action || incident.requested_action || "",
      resolution_notes: workflowData.resolution_notes || incident.resolution_notes || "",
      close_reason: workflowData.close_reason || incident.close_reason || "",
    });
    setVerdict(incident.analyst_verdict || "undecided");
    setVerdictReason(incident.verdict_reason || "");
  }, [incident, workflowData.queue, workflowData.assignee, workflowData.priority, workflowData.workflow_status, workflowData.sla_due_at, workflowData.first_ack_due_at, workflowData.resolve_due_at, workflowData.escalation_level, workflowData.requested_action, workflowData.resolution_notes, workflowData.close_reason]);

  const triage = useMemo(() => {
    const events = [...evidence, ...triggeringEvents];
    const entities = incident?.entities || {};
    const sourceIps = unique([entities.source_ip, ...events.map((e) => e.source_ip)]);
    const destIps = unique([entities.destination_ip, ...events.map((e) => e.destination_ip)]);
    const users = unique([entities.user, ...events.map((e) => e.user || e.email || e.user_email)]);
    const hosts = unique([entities.host, ...events.map((e) => e.host)]);
    const times = events
      .map((e) => e.event_time || e.time || e._time)
      .filter(Boolean)
      .map((v) => new Date(v))
      .filter((d) => !Number.isNaN(d.getTime()));
    const sorted = times.sort((a, b) => a - b);
    return { sourceIps, destIps, users, hosts, firstSeen: sorted[0], lastSeen: sorted[sorted.length - 1], eventCount: events.length };
  }, [incident, evidence, triggeringEvents]);

  function showToast(message) {
    setToast(message);
    setTimeout(() => setToast(null), 2500);
  }

  async function patchIncident(patch) {
    setActionError(null);
    await updateIncidentMutation.mutateAsync({ id, patch });
    await incidentQuery.refetch();
  }

  async function saveNotes() {
    try {
      await patchIncident({ notes });
      showToast("Notes saved");
    } catch (e) {
      setActionError(e?.message || "Failed to save notes");
    }
  }

  async function saveDecision() {
    try {
      await patchIncident({ analyst_verdict: verdict, verdict_reason: verdictReason });
      showToast("Analyst decision saved");
    } catch (e) {
      setActionError(e?.message || "Failed to save analyst decision");
    }
  }

  async function downloadPdf() {
    try {
      const blob = await downloadPdfMutation.mutateAsync(id);
      const url = URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `incident-${id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setActionError(e?.message || "Failed to generate PDF report");
    }
  }

  async function setApproval(approval_status) {
    try {
      await patchIncident({ approval_status });
      showToast(approval_status === "approved" ? "Candidate approved" : "Candidate rejected");
    } catch (e) {
      setActionError(e?.message || "Failed to update approval");
    }
  }

  async function addTriggeringEvents() {
    try {
      const data = await bulkAddEvidenceMutation.mutateAsync({ incidentId: id, events: triggeringEvents });
      await incidentQuery.refetch();
      showToast(`Added ${data.added || 0} triggering logs`);
    } catch (e) {
      setActionError(e?.message || "Failed to add evidence");
    }
  }

  async function deleteIncidentAction() {
    try {
      await deleteIncidentMutation.mutateAsync(id);
      sessionStorage.setItem("ztx_incident_deleted", "Incident deleted");
      navigate("/incidents");
    } catch (e) {
      setActionError(e?.message || "Failed to delete incident");
    }
  }

  async function handleStatusChange(value) {
    try {
      await patchIncident({ status: value });
    } catch (e) {
      setActionError(e?.message || "Failed to update incident status");
    }
  }

  function updateWorkflow(key, value) {
    setWorkflow((current) => ({ ...current, [key]: value }));
  }

  async function saveWorkflow() {
    try {
      await updateWorkflowMutation.mutateAsync({
        id,
        patch: {
          ...workflow,
          escalation_level: Number(workflow.escalation_level || 0),
          sla_due_at: workflow.sla_due_at || null,
          first_ack_due_at: workflow.first_ack_due_at || null,
          resolve_due_at: workflow.resolve_due_at || null,
        },
      });
      await incidentQuery.refetch();
      await activityQuery.refetch();
      showToast("Workflow updated");
    } catch (e) {
      setActionError(e?.message || "Failed to update workflow");
    }
  }

  async function addComment() {
    const body = comment.trim();
    if (!body) return;
    try {
      await addCommentMutation.mutateAsync({ id, body });
      setComment("");
      await commentsQuery.refetch();
      await activityQuery.refetch();
      showToast("Comment added");
    } catch (e) {
      setActionError(e?.message || "Failed to add comment");
    }
  }

  if (incidentQuery.isLoading) {
    return (
      <>
        <PageHeader title="Incident" subtitle="Loading incident context" />
        <div style={{ padding: 24, color: "var(--t3)" }}>Loading incident...</div>
      </>
    );
  }

  if (incidentQuery.error) {
    const status = incidentQuery.error?.status;
    if (status === 403) {
      return (
        <IncidentPageState
          title="You do not have permission to view this incident."
          message={incidentQuery.error.message}
          tone="error"
          onAction={() => navigate("/incidents")}
        />
      );
    }
    if (status === 404) {
      return (
        <IncidentPageState
          title="Incident not found."
          message={incidentQuery.error.message}
          tone="error"
          onAction={() => navigate("/incidents")}
          onSecondaryAction={() => incidentQuery.refetch()}
          secondaryLabel="Retry"
        />
      );
    }
    return (
      <IncidentPageState
        title="Could not load incident."
        message={incidentQuery.error?.message || "Unknown error"}
        tone="error"
        onAction={() => navigate("/incidents")}
        onSecondaryAction={() => incidentQuery.refetch()}
        secondaryLabel="Retry"
      />
    );
  }

  if (!incident) {
    return (
      <IncidentPageState
        title="Incident not found."
        message="No incident data was returned for this record."
        tone="error"
        onAction={() => navigate("/incidents")}
        onSecondaryAction={() => incidentQuery.refetch()}
        secondaryLabel="Retry"
      />
    );
  }

  const alert = triggered?.alert || {};
  const canContain = triage.sourceIps[0];

  return (
    <>
      <PageHeader
        title={
          <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
            <Link to="/incidents" style={{ color: "var(--t3)", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 5, fontSize: 13 }}>
              <ArrowLeft size={14} /> Incidents
            </Link>
            <SeverityBadge severity={incident.severity} />
            <span style={{ fontSize: 18, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{incident.title}</span>
          </div>
        }
        subtitle={`${incident.source || "analyst"} | ${incident.evidence_count || 0} evidence items | updated ${fmtTs(incident.updated_at || incident.created_at)}`}
        actions={
          <>
            {canExport && <Button variant="secondary" onClick={downloadPdf} disabled={downloadPdfMutation.isPending}><Download size={14} /> {downloadPdfMutation.isPending ? "Generating" : "PDF report"}</Button>}
            <AppSelect value={incident.status} onChange={handleStatusChange} options={STATUSES} disabled={!canWrite || saving} style={{ width: 180 }} />
            {canApprove && incident.status === "pending_approval" && (
              <>
                <Button variant="secondary" onClick={() => setApproval("approved")} disabled={saving}>Approve</Button>
                <Button variant="ghost" onClick={() => setApproval("rejected")} disabled={saving}>Reject</Button>
              </>
            )}
            {canDelete && <Button variant="danger" onClick={() => setDeleteOpen(true)}><Trash2 size={14} /> Delete</Button>}
          </>
        }
      />

      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
        {toast && <Banner><CheckCircle2 size={15} /> {toast}</Banner>}
        {actionError && <Banner tone="error"><XCircle size={15} /> {actionError}</Banner>}
        {!incident.is_active && incident.status !== "pending_approval" && (
          <Banner>Pending Evidence: this incident becomes active after at least one log is attached.</Banner>
        )}

        <Card>
          <CardLabel>Executive Summary</CardLabel>
          <InfoGrid items={[
            ["Severity", incident.severity],
            ["Status", incident.status?.replace(/_/g, " ")],
            ["Activation", incident.activation_state?.replace(/_/g, " ")],
            ["Confidence", incident.confidence ? `${Math.round(incident.confidence * 100)}%` : "-"],
            ["Owner", incident.owner || "Unassigned"],
            ["Approval", incident.approval_status || "approved"],
            ["Verdict", (incident.analyst_verdict || "undecided").replace(/_/g, " ")],
            ["Occurrences", incident.occurrence_count || 1],
            ["Created", fmtTs(incident.created_at)],
            ["Updated", fmtTs(incident.updated_at)],
            ["Source", incident.source],
          ]} />
        </Card>

        <Card>
          <CardLabel>Triage Summary</CardLabel>
          <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 16 }}>
            <div>
              <div style={{ color: "var(--t1)", fontWeight: 700, marginBottom: 6 }}>What happened?</div>
              <div style={{ color: "var(--t2)", fontSize: 13, lineHeight: 1.55 }}>{incident.description || "No description provided."}</div>
              <div style={{ color: "var(--t1)", fontWeight: 700, margin: "14px 0 6px" }}>Why is it suspicious?</div>
              <div style={{ color: "var(--t2)", fontSize: 13, lineHeight: 1.55 }}>
                {isSplunkCandidate
                  ? "Splunk recorded a fired alert. Review the detection SPL and triggering logs before approving or attaching evidence."
                  : "Manual incident. Attach investigation logs to activate and establish evidence."}
              </div>
            </div>
            <InfoGrid items={[
              ["Affected users", triage.users.join(", ")],
              ["Affected hosts", triage.hosts.join(", ")],
              ["Source IPs", triage.sourceIps.join(", ")],
              ["Destination IPs", triage.destIps.join(", ")],
              ["First seen", triage.firstSeen ? fmtTs(triage.firstSeen) : "-"],
              ["Last seen", triage.lastSeen ? fmtTs(triage.lastSeen) : "-"],
              ["Event count", triage.eventCount],
              ["Evidence count", incident.evidence_count || 0],
              ["Category", incident.category || "-"],
            ]} />
          </div>
        </Card>

        <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)", gap: 20 }}>
          <Card>
            <CardLabel>Analyst Decision</CardLabel>
            <div style={{ display: "grid", gap: 10 }}>
              <AppSelect value={verdict} onChange={setVerdict} options={VERDICTS} disabled={!canWrite} />
              <Textarea
                value={verdictReason}
                onChange={(e) => setVerdictReason(e.target.value)}
                disabled={!canWrite}
                placeholder="Decision reason, duplicate reference, or additional context"
                style={{ minHeight: 86 }}
              />
              <Button variant="secondary" onClick={saveDecision} disabled={!canWrite || saving}>
                Save decision
              </Button>
              {incident.verdict_by && (
                <div style={{ color: "var(--t3)", fontSize: 12 }}>
                  Last decision by {incident.verdict_by} at {fmtTs(incident.verdict_at)}
                </div>
              )}
            </div>
          </Card>

          <Card>
            <IncidentDetailErrorBoundary
              resetKey={`${id}-mitre-summary`}
              fallback={<EmptyState title="MITRE mapping unavailable" subtitle="The MITRE summary failed to render. You can still review the incident and reopen mapping later." />}
            >
              <IncidentMitreSummaryCard incidentId={id} canWrite={canWrite} onOpen={() => setMitreOpen(true)} />
            </IncidentDetailErrorBoundary>
          </Card>
        </div>

        {isSplunkCandidate && (
          <Card>
            <CardLabel>Triggered Splunk Alert</CardLabel>
            {triggered?.error && <Banner tone="error"><XCircle size={15} /> {triggered.error}</Banner>}
            {triggeredQuery.error && <Banner tone="error"><XCircle size={15} /> {triggeredQuery.error.message}</Banner>}
            <div style={{ marginTop: triggered?.error || triggeredQuery.error ? 12 : 0 }}>
              <InfoGrid items={[
                ["Alert name", alert.name || incident.title],
                ["Saved search", alert.saved_search_name || alert.search_name || incident.linked_splunk_alert_id],
                ["Trigger time", fmtTs(alert.trigger_time)],
                ["Result count", alert.result_count ?? triggered?.count ?? 0],
                ["Status", alert.status || incident.status],
                ["Trigger condition", alert.trigger_condition || "-"],
              ]} />
            </div>
            <div style={{ marginTop: 12 }}>
              <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>Detection SPL</div>
              <pre className="mono scrollbar-thin" style={{ margin: 0, maxHeight: 160, overflow: "auto", whiteSpace: "pre-wrap", color: "var(--t2)", background: "var(--s1)", border: "1px solid var(--b0)", borderRadius: 8, padding: 12 }}>
                {triggered?.query || alert.search || "No SPL query available from Splunk."}
              </pre>
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
              <Button variant="secondary" onClick={addTriggeringEvents} disabled={!triggeringEvents.length || bulkAddEvidenceMutation.isPending}>Add triggering logs as evidence</Button>
              <Button variant="ghost" onClick={() => navigate("/investigation")}><ExternalLink size={14} /> Open Investigation</Button>
            </div>
            <div style={{ marginTop: 14 }}>
              <EventTable events={triggeringEvents} onView={setRawView} reputationByIp={reputationByIp} canRefreshReputation={canWrite} />
            </div>
          </Card>
        )}

        <Card>
          <CardLabel>Evidence Timeline</CardLabel>
          <EvidenceTimeline
            events={evidence}
            selectedId={selectedEvidenceId}
            onSelect={(event, eventId) => {
              setSelectedEvidenceId(eventId);
              setRawView(event);
            }}
          />
        </Card>

        <Card>
          <CardLabel>Evidence Table</CardLabel>
          {evidence.length ? (
            <EventTable
              events={evidence}
              reputationByIp={reputationByIp}
              canRefreshReputation={canWrite}
              onView={(event) => {
                setSelectedEvidenceId(event.event_hash || event.id || null);
                setRawView(event);
              }}
            />
          ) : (
            <EmptyState title="No evidence attached" subtitle="Attach triggering logs or investigation logs to activate this incident." />
          )}
        </Card>

        <Card>
          <CardLabel>Observables / Entities</CardLabel>
          {reputationQuery.error && <Banner tone="error"><XCircle size={15} /> {reputationQuery.error.message}</Banner>}
          {(reputationQuery.data?.reputations || []).length > 0 && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              {(reputationQuery.data?.reputations || []).map((item) => (
                <IpReputationBadge key={item.ip_address} ip={item.ip_address} reputation={item} canRefresh={canWrite} />
              ))}
            </div>
          )}
          <InfoGrid items={[
            ["Users", (observables.users.length ? observables.users : triage.users).join(", ")],
            ["Hosts", (observables.hosts.length ? observables.hosts : triage.hosts).join(", ")],
            ["Source IPs", (observables.source_ips.length ? observables.source_ips : triage.sourceIps).join(", ")],
            ["Destination IPs", (observables.destination_ips.length ? observables.destination_ips : triage.destIps).join(", ")],
            ["URLs", observables.urls.join(", ")],
            ["Domains", observables.domains.join(", ")],
            ["Hashes", observables.hashes.join(", ")],
            ["Files", observables.files.join(", ")],
          ]} />
        </Card>

        <Card>
          <CardLabel>Workflow / SLA</CardLabel>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 10 }}>
            <Input value={workflow.queue || ""} onChange={(e) => updateWorkflow("queue", e.target.value)} disabled={!canWrite} placeholder="Queue" />
            <Input value={workflow.owner || ""} onChange={(e) => updateWorkflow("owner", e.target.value)} disabled={!canWrite} placeholder="Assignee" />
            <AppSelect value={workflow.priority || "medium"} onChange={(value) => updateWorkflow("priority", value)} options={PRIORITIES} disabled={!canWrite} />
            <AppSelect value={workflow.workflow_status || "open"} onChange={(value) => updateWorkflow("workflow_status", value)} options={WORKFLOW_STATUSES} disabled={!canWrite} />
            <Input type="datetime-local" value={workflow.first_ack_due_at || ""} onChange={(e) => updateWorkflow("first_ack_due_at", e.target.value)} disabled={!canWrite} />
            <Input type="datetime-local" value={workflow.resolve_due_at || ""} onChange={(e) => updateWorkflow("resolve_due_at", e.target.value)} disabled={!canWrite} />
            <Input type="datetime-local" value={workflow.sla_due_at || ""} onChange={(e) => updateWorkflow("sla_due_at", e.target.value)} disabled={!canWrite} />
            <Input type="number" min="0" max="5" value={workflow.escalation_level || "0"} onChange={(e) => updateWorkflow("escalation_level", e.target.value)} disabled={!canWrite} placeholder="Escalation" />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 10, marginTop: 10 }}>
            <Textarea value={workflow.requested_action || ""} onChange={(e) => updateWorkflow("requested_action", e.target.value)} disabled={!canWrite} placeholder="Requested action / remediation task" style={{ minHeight: 80 }} />
            <Textarea value={workflow.resolution_notes || ""} onChange={(e) => updateWorkflow("resolution_notes", e.target.value)} disabled={!canWrite} placeholder="Resolution notes" style={{ minHeight: 80 }} />
            <Textarea value={workflow.close_reason || ""} onChange={(e) => updateWorkflow("close_reason", e.target.value)} disabled={!canWrite} placeholder="Close reason" style={{ minHeight: 80 }} />
          </div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginTop: 10 }}>
            <div style={{ color: "var(--t3)", fontSize: 12 }}>
              SLA state: <StatusBadge status={workflowData.sla_state || incident.sla_state || "no_sla"} />
            </div>
            <Button variant="secondary" onClick={saveWorkflow} disabled={!canWrite || updateWorkflowMutation.isPending}>
              {updateWorkflowMutation.isPending ? "Saving..." : "Save workflow"}
            </Button>
          </div>
        </Card>

        <Card>
          <CardLabel>Comments / Activity</CardLabel>
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)", gap: 16 }}>
            <div style={{ display: "grid", gap: 10 }}>
              <Textarea value={comment} onChange={(e) => setComment(e.target.value)} disabled={!canWrite} placeholder="Add internal analyst comment" style={{ minHeight: 88 }} />
              <Button variant="secondary" onClick={addComment} disabled={!canWrite || addCommentMutation.isPending || !comment.trim()}>
                {addCommentMutation.isPending ? "Adding..." : "Add comment"}
              </Button>
              {comments.length ? comments.map((item) => (
                <div key={item.id} style={{ border: "1px solid var(--b0)", borderRadius: 8, padding: 10, background: "var(--s1)" }}>
                  <div style={{ color: "var(--t1)", fontSize: 13, lineHeight: 1.5 }}>{item.body}</div>
                  <div className="mono" style={{ color: "var(--t3)", fontSize: 11, marginTop: 6 }}>{item.created_by || "-"} | {fmtTs(item.created_at)}</div>
                </div>
              )) : <EmptyState title="No comments yet" subtitle="Analyst comments and internal notes appear here." />}
            </div>
            <div style={{ display: "grid", gap: 8, alignContent: "start" }}>
              {activity.length ? activity.map((item) => (
                <div key={item.id} style={{ borderLeft: "2px solid rgba(59,130,246,0.45)", padding: "4px 0 8px 10px" }}>
                  <div style={{ color: "var(--t1)", fontSize: 13 }}>{item.summary}</div>
                  <div className="mono" style={{ color: "var(--t3)", fontSize: 11, marginTop: 4 }}>{item.activity_type} | {item.actor || "-"} | {fmtTs(item.created_at)}</div>
                </div>
              )) : <EmptyState title="No activity yet" subtitle="Status, evidence, workflow, verdict, comments, and response events are recorded here." />}
            </div>
          </div>
        </Card>

        <Card>
          <CardLabel>Response Actions</CardLabel>
          <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 16, alignItems: "start" }}>
            <div>
              <div style={{ color: "var(--t2)", fontSize: 13, marginBottom: 8 }}>Analyst notes</div>
              <Textarea value={notes} onChange={(e) => setNotes(e.target.value)} disabled={!canWrite} placeholder="Triage notes, decisions, containment steps" style={{ minHeight: 90 }} />
              <Button variant="secondary" onClick={saveNotes} disabled={!canWrite || saving} style={{ marginTop: 8 }}>{saving ? "Saving" : "Save notes"}</Button>
            </div>
            <div style={{ minWidth: 240 }}>
              <div style={{ color: "var(--t2)", fontSize: 13, marginBottom: 8 }}>Containment</div>
              {!canWrite ? (
                <div style={{ color: "var(--t3)", fontSize: 13, border: "1px solid var(--b0)", borderRadius: 8, padding: 12 }}>
                  Viewer role can inspect containment history but cannot run firewall actions.
                </div>
              ) : canContain ? (
                <ContainmentButton incidentId={incident.id} targetIp={canContain} alias={null} onDone={() => incidentQuery.refetch()} />
              ) : (
                <div style={{ color: "var(--t3)", fontSize: 13, border: "1px solid var(--b0)", borderRadius: 8, padding: 12 }}>
                  <Shield size={14} /> No source IP available for pfSense containment.
                </div>
              )}
            </div>
          </div>
          <div style={{ marginTop: 16 }}>
            <div style={{ color: "var(--t2)", fontSize: 13, marginBottom: 8 }}>Containment audit trail</div>
            {containmentActions.length ? (
              <Table
                columns={[
                  { key: "requested_at", label: "Requested", render: (r) => <span className="mono">{fmtTs(r.requested_at)}</span> },
                  { key: "action_type", label: "Action", render: (r) => text(r.action_type).replace(/_/g, " ") },
                  { key: "target_ip", label: "Target", render: (r) => <span className="mono">{text(r.target_ip)}</span> },
                  { key: "requested_by", label: "By", render: (r) => text(r.requested_by) },
                  { key: "status", label: "Status", render: (r) => <StatusBadge status={r.status} /> },
                  { key: "reason", label: "Reason", render: (r) => text(r.reason) },
                ]}
                rows={containmentActions}
                rowKey={(r) => r.id}
                empty="No containment actions recorded"
                pagination
                pageSize={8}
              />
            ) : (
              <EmptyState title="No containment actions recorded" subtitle="Firewall actions will appear here with who, when, target IP, reason, and result." />
            )}
          </div>
        </Card>
      </div>

      <Modal open={!!rawView} onClose={() => setRawView(null)} title="Log Details" maxWidth={820}>
        {rawView && (
          <div style={{ display: "grid", gap: 14 }}>
            <InfoGrid items={[
              ["Time", fmtTs(rawView.event_time || rawView.time || rawView._time)],
              ["Severity", rawView.severity || rawView.level || "unknown"],
              ["Source IP", rawView.source_ip],
              ["Destination IP", rawView.destination_ip],
              ["User", rawView.user || rawView.email || rawView.user_email],
              ["Host", rawView.host],
              ["Action", rawView.action],
              ["Category", rawView.category],
              ["Status", rawView.status_code],
            ]} />
            <div style={{ color: "var(--t2)", fontSize: 13, lineHeight: 1.55 }}>
              {eventMessage(rawView)}
            </div>
            <details>
              <summary style={{ color: "var(--t2)", cursor: "pointer", fontWeight: 700 }}>Raw event JSON</summary>
              <pre className="mono scrollbar-thin" style={{
                marginTop: 10,
                maxHeight: 420,
                overflow: "auto",
                whiteSpace: "pre-wrap",
                color: "var(--t2)",
                background: "var(--s1)",
                border: "1px solid var(--b0)",
                borderRadius: 8,
                padding: 14,
              }}>
                {JSON.stringify(rawView.raw_event || rawView.raw_data || rawView.raw || rawView, null, 2)}
              </pre>
            </details>
          </div>
        )}
      </Modal>

      <IncidentDetailErrorBoundary resetKey={`${id}-mitre-workspace-${mitreOpen ? "open" : "closed"}`} fallback={null}>
        <IncidentMitreWorkspace
          open={mitreOpen}
          onClose={() => setMitreOpen(false)}
          incidentId={id}
          canWrite={canWrite}
          canAdmin={user?.role === "admin"}
        />
      </IncidentDetailErrorBoundary>

      <Modal open={deleteOpen} onClose={deleteIncidentMutation.isPending ? undefined : () => setDeleteOpen(false)} title="Delete Incident" maxWidth={520}>
        <div style={{ display: "grid", gap: 14 }}>
          <Banner tone="error">
            <Trash2 size={15} /> This will permanently delete this incident and its evidence. This action cannot be undone.
          </Banner>
          <div style={{ color: "var(--t2)", fontSize: 13 }}>
            Incident: <strong style={{ color: "var(--t1)" }}>{incident.title}</strong>
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
            <Button variant="ghost" onClick={() => setDeleteOpen(false)} disabled={deleteIncidentMutation.isPending}>Cancel</Button>
            <Button variant="danger" onClick={deleteIncidentAction} disabled={deleteIncidentMutation.isPending}>
              <Trash2 size={14} /> {deleteIncidentMutation.isPending ? "Deleting..." : "Delete permanently"}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Warning as AlertTriangle, CheckCircle as CheckCircle2, CaretRight as ChevronRight, Plus, ArrowClockwise as RefreshCw, MagnifyingGlass as Search, X } from "@phosphor-icons/react";
import PageHeader from "../../components/layout/PageHeader";
import Button from "../../components/ui/Button";
import Input, { Textarea } from "../../components/ui/Input";
import AppSelect from "../../components/ui/AppSelect";
import Modal from "../../components/ui/Modal";
import SeverityBadge from "../../components/ui/SeverityBadge";
import StatusBadge from "../../components/ui/StatusBadge";
import EmptyState from "../../components/ui/EmptyState";
import Table from "../../components/ui/Table";
import IpReputationBadge from "../../components/reputation/IpReputationBadge";
import { getApiError } from "../../api/client";
import { useAuth } from "../../context/AuthContext";
import {
  incidentListFrom,
  useCreateIncident,
  useIncidentsQuery,
  useSyncSplunkAlertIncidents,
  useUpdateIncident,
} from "../../hooks/queries/useIncidentQueries";
import { nextSort, sortRows } from "../../utils/sort";

const STATUS_OPTIONS = [
  ["", "All statuses"],
  ["draft", "Draft"],
  ["pending_evidence", "Pending Evidence"],
  ["pending_approval", "Pending Approval"],
  ["new", "New"],
  ["triage", "Triage"],
  ["investigating", "Investigating"],
  ["contained", "Contained"],
  ["monitoring", "Monitoring"],
  ["resolved", "Resolved"],
  ["closed", "Closed"],
  ["rejected", "Rejected"],
].map(([value, label]) => ({ value, label }));

const SEVERITY_OPTIONS = [
  ["", "All severities"],
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["informational", "Informational"],
].map(([value, label]) => ({ value, label }));

const CREATE_SEVERITIES = SEVERITY_OPTIONS.filter((o) => o.value);
const CREATE_STATUSES = [
  { value: "pending_evidence", label: "Pending Evidence" },
  { value: "draft", label: "Draft" },
];
const CATEGORY_OPTIONS = [
  ["authentication", "Authentication"],
  ["network", "Network"],
  ["web", "Web"],
  ["endpoint", "Endpoint"],
  ["firewall", "Firewall"],
  ["malware", "Malware"],
  ["data_exfiltration", "Data Exfiltration"],
  ["reconnaissance", "Reconnaissance"],
  ["policy_violation", "Policy Violation"],
  ["other", "Other"],
].map(([value, label]) => ({ value, label }));

const SOURCE_OPTIONS = [
  ["", "All sources"],
  ["analyst", "Analyst"],
  ["splunk", "Splunk"],
].map(([value, label]) => ({ value, label }));

const SEVERITY_PILLS = [
  { value: "", label: "All", color: "var(--t3)", bg: "var(--s1)" },
  { value: "critical", label: "Critical", color: "#DC2626", bg: "rgba(220,38,38,0.12)" },
  { value: "high", label: "High", color: "#EA580C", bg: "rgba(234,88,12,0.12)" },
  { value: "medium", label: "Medium", color: "#CA8A04", bg: "rgba(202,138,4,0.12)" },
  { value: "low", label: "Low", color: "#22C55E", bg: "rgba(34,197,94,0.12)" },
  { value: "informational", label: "Info", color: "#64748B", bg: "rgba(100,116,139,0.12)" },
];

function emptyForm() {
  return {
    title: "",
    severity: "medium",
    status: "pending_evidence",
    category: "other",
    description: "",
    owner: "",
    tags: "",
    source_ip: "",
    destination_ip: "",
    user: "",
    host: "",
    notes: "",
  };
}

function fmtTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString().replace("T", " ").slice(0, 19);
}

function Banner({ tone = "info", children }) {
  const isError = tone === "error";
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
    }}>
      {children}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
      <span style={{ fontSize: 11, color: "var(--t3)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</span>
      {children}
    </label>
  );
}

function CreateIncidentModal({ open, onClose, onSubmit, pending }) {
  const [form, setForm] = useState(emptyForm());
  const [error, setError] = useState(null);

  useEffect(() => {
    if (open) {
      setForm(emptyForm());
      setError(null);
    }
  }, [open]);

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function submit() {
    setError(null);
    if (!form.title.trim()) return setError("Title is required.");
    if (!form.description.trim()) return setError("Description is required.");
    try {
      await onSubmit({
        title: form.title.trim(),
        description: form.description.trim(),
        severity: form.severity,
        status: form.status,
        category: form.category,
        source: "analyst",
        owner: form.owner.trim() || null,
        tags: form.tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        entities: {
          source_ip: form.source_ip.trim(),
          destination_ip: form.destination_ip.trim(),
          user: form.user.trim(),
          host: form.host.trim(),
        },
        detection_source: "manual",
        notes: form.notes.trim(),
      });
    } catch (err) {
      setError(getApiError(err, "Failed to create incident"));
    }
  }

  return (
    <Modal open={open} onClose={pending ? undefined : onClose} title="Create Incident" maxWidth={760}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {error && <Banner tone="error"><AlertTriangle size={15} /> {error}</Banner>}
        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 170px 180px", gap: 10 }}>
          <Field label="Title"><Input value={form.title} onChange={(event) => update("title", event.target.value)} placeholder="Suspicious authentication activity" /></Field>
          <Field label="Severity"><AppSelect value={form.severity} onChange={(value) => update("severity", value)} options={CREATE_SEVERITIES} /></Field>
          <Field label="Status"><AppSelect value={form.status} onChange={(value) => update("status", value)} options={CREATE_STATUSES} /></Field>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 10 }}>
          <Field label="Category"><AppSelect value={form.category} onChange={(value) => update("category", value)} options={CATEGORY_OPTIONS} /></Field>
          <Field label="Description"><Textarea value={form.description} onChange={(event) => update("description", event.target.value)} placeholder="What is being investigated?" style={{ minHeight: 76 }} /></Field>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10 }}>
          <Field label="Source IP"><Input value={form.source_ip} onChange={(event) => update("source_ip", event.target.value)} /></Field>
          <Field label="Destination IP"><Input value={form.destination_ip} onChange={(event) => update("destination_ip", event.target.value)} /></Field>
          <Field label="User / Email"><Input value={form.user} onChange={(event) => update("user", event.target.value)} /></Field>
          <Field label="Host"><Input value={form.host} onChange={(event) => update("host", event.target.value)} /></Field>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <Field label="Owner / Assignee"><Input value={form.owner} onChange={(event) => update("owner", event.target.value)} /></Field>
          <Field label="Tags"><Input value={form.tags} onChange={(event) => update("tags", event.target.value)} placeholder="auth, suspicious, priority" /></Field>
        </div>
        <Field label="Notes"><Textarea value={form.notes} onChange={(event) => update("notes", event.target.value)} style={{ minHeight: 70 }} /></Field>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10 }}>
          <Button variant="ghost" onClick={onClose} disabled={pending}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={pending || !form.title.trim() || !form.description.trim()}>
            {pending ? "Creating..." : "Create incident"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export default function IncidentQueue() {
  const { user } = useAuth();
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [toast, setToast] = useState(null);
  const [error, setError] = useState(null);
  const [sort, setSort] = useState({ key: "updated_at", direction: "desc" });

  useEffect(() => { document.title = "Incidents - ZeroTrustX"; }, []);

  const filters = useMemo(() => ({
    status: statusFilter,
    severity: severityFilter,
    source: sourceFilter,
    search,
  }), [statusFilter, severityFilter, sourceFilter, search]);
  const incidentsQuery = useIncidentsQuery(filters);
  const createMutation = useCreateIncident();
  const updateMutation = useUpdateIncident();
  const syncMutation = useSyncSplunkAlertIncidents();

  useEffect(() => {
    syncMutation.mutate(undefined, { onSettled: () => incidentsQuery.refetch() });
  }, []);

  const rows = incidentListFrom(incidentsQuery.data || {});
  const sortedRows = useMemo(() => sortRows(rows, sort, {
    title: (incident) => incident.title,
    severity: (incident) => incident.severity,
    status: (incident) => incident.status,
    owner: (incident) => incident.owner,
    analyst_verdict: (incident) => incident.analyst_verdict,
    evidence_count: (incident) => incident.evidence_count || 0,
    related_alert_count: (incident) => incident.related_alert_count || 0,
    sla_state: (incident) => incident.sla_state,
    updated_at: (incident) => incident.updated_at || incident.created_at,
  }), [rows, sort]);

  const pendingEvidence = rows.filter((incident) => !incident.is_active && incident.status !== "pending_approval" && incident.status !== "rejected").length;
  const pendingApproval = rows.filter((incident) => incident.status === "pending_approval").length;
  const active = rows.filter((incident) => incident.is_active).length;
  const canWrite = !["viewer", "degraded"].includes(user?.role);
  const canApprove = user?.role === "admin";
  const hasFilters = Boolean(statusFilter || severityFilter || sourceFilter || search);
  const listError = error || incidentsQuery.error?.message || incidentsQuery.data?.error || null;

  function showToast(message) {
    setToast(message);
    setTimeout(() => setToast(null), 2600);
  }

  async function createIncident(payload) {
    await createMutation.mutateAsync(payload);
    setCreateOpen(false);
    showToast("Incident created");
  }

  async function updateApproval(incident, approval_status) {
    setError(null);
    try {
      await updateMutation.mutateAsync({ id: incident.id, patch: { approval_status } });
      showToast(approval_status === "approved" ? "Incident approved" : "Incident rejected");
    } catch (err) {
      setError(getApiError(err, "Failed to update incident"));
    }
  }

  function clearFilters() {
    setStatusFilter("");
    setSeverityFilter("");
    setSourceFilter("");
    setSearch("");
  }

  return (
    <>
      <PageHeader
        title="Incidents"
        subtitle={`${rows.length} total · ${active} active · ${pendingEvidence} pending evidence · ${pendingApproval} pending approval`}
        actions={
          <>
            <Button
              variant="secondary"
              onClick={() => syncMutation.mutate(undefined, { onSettled: () => incidentsQuery.refetch() })}
              disabled={!canWrite || syncMutation.isPending || incidentsQuery.isFetching}
            >
              <RefreshCw size={14} /> {syncMutation.isPending || incidentsQuery.isFetching ? "Syncing..." : "Refresh"}
            </Button>
            <Button variant="primary" onClick={() => setCreateOpen(true)} disabled={!canWrite}>
              <Plus size={14} /> Create incident
            </Button>
          </>
        }
      />

      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
        {toast && <Banner><CheckCircle2 size={15} /> {toast}</Banner>}
        {listError && <Banner tone="error"><AlertTriangle size={15} /> {listError}</Banner>}

        <div style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: 14, display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "grid", gridTemplateColumns: "190px 190px 1fr auto", gap: 12, alignItems: "end" }}>
            <Field label="Status"><AppSelect value={statusFilter} onChange={setStatusFilter} options={STATUS_OPTIONS} /></Field>
            <Field label="Source"><AppSelect value={sourceFilter} onChange={setSourceFilter} options={SOURCE_OPTIONS} /></Field>
            <Field label="Search">
              <div style={{ position: "relative" }}>
                <Search size={14} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--t3)", pointerEvents: "none" }} />
                <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Title, description, owner..." style={{ paddingLeft: 32 }} />
              </div>
            </Field>
            {hasFilters && (
              <button type="button" onClick={clearFilters} style={{
                alignSelf: "center",
                marginTop: 14,
                background: "transparent",
                border: "none",
                color: "var(--t3)",
                cursor: "pointer",
                fontSize: 12,
                display: "flex",
                alignItems: "center",
                gap: 4,
                padding: "6px 8px",
                borderRadius: 6,
              }}>
                <X size={12} /> Clear
              </button>
            )}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
            <span style={{ fontSize: 10, color: "var(--t4)", textTransform: "uppercase", letterSpacing: "0.06em", marginRight: 4, flexShrink: 0 }}>
              Severity
            </span>
            {SEVERITY_PILLS.map((pill) => {
              const activePill = severityFilter === pill.value;
              return (
                <button
                  key={pill.value}
                  type="button"
                  onClick={() => setSeverityFilter(activePill ? "" : pill.value)}
                  style={{
                    padding: "3px 10px",
                    borderRadius: 20,
                    border: `1px solid ${activePill ? pill.color : "rgba(255,255,255,0.08)"}`,
                    background: activePill ? pill.bg : "transparent",
                    color: activePill ? pill.color : "var(--t3)",
                    fontSize: 11,
                    fontWeight: activePill ? 600 : 400,
                    cursor: "pointer",
                    letterSpacing: "0.02em",
                    whiteSpace: "nowrap",
                  }}
                >
                  {pill.label}
                </button>
              );
            })}
          </div>
        </div>

        <Table
          columns={[
            { key: "severity", label: "Severity", render: (incident) => <SeverityBadge severity={incident.severity} /> },
            { key: "title", label: "Title", render: (incident) => (
              <div style={{ minWidth: 0 }}>
                <Link to={`/incidents/${incident.id}`} style={{ color: "var(--t1)", textDecoration: "none", fontWeight: 700, fontSize: 13 }} title={incident.title}>
                  <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "normal", lineHeight: 1.35 }}>{incident.title}</span>
                </Link>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 3, minWidth: 0 }}>
                  <span className="mono" style={{ color: "#475569", fontSize: 10 }}>#{incident.id.slice(0, 8)}</span>
                  {incident.description && <span style={{ color: "var(--t3)", fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{incident.description}</span>}
                </div>
              </div>
            ) },
            { key: "status", label: "Status", render: (incident) => <StatusBadge status={incident.status} /> },
            { key: "analyst_verdict", label: "Verdict", render: (incident) => <span style={{ color: "var(--t3)" }}>{(incident.analyst_verdict || "undecided").replace(/_/g, " ")}</span> },
            { key: "owner", label: "Assignee", render: (incident) => <span style={{ color: "var(--t3)" }}>{incident.owner || "Unassigned"}</span> },
            { key: "evidence_count", label: "Evidence", render: (incident) => <span className="mono">{incident.evidence_count || 0}</span> },
            { key: "related_alert_count", label: "Alerts", render: (incident) => <span className="mono">{incident.related_alert_count || 0}</span> },
            { key: "ip_reputation", label: "IP Rep", render: (incident) => (
              <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                {(incident.ip_reputation || []).slice(0, 2).map((item) => (
                  <IpReputationBadge key={item.ip_address} ip={item.ip_address} reputation={item} canRefresh={canWrite} />
                ))}
              </div>
            ) },
            { key: "sla_state", label: "SLA", render: (incident) => <StatusBadge status={incident.sla_state || "no_sla"} /> },
            { key: "updated_at", label: "Updated", render: (incident) => <span className="mono" style={{ color: "var(--t3)", fontSize: 11 }}>{fmtTime(incident.updated_at || incident.created_at)}</span> },
            { key: "actions", label: "", sortable: false, render: (incident) => (
              canApprove && incident.status === "pending_approval" ? (
                <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                  <Button variant="secondary" onClick={(event) => { event.stopPropagation(); updateApproval(incident, "approved"); }} style={{ padding: "4px 8px", fontSize: 11 }}>Approve</Button>
                  <Button variant="ghost" onClick={(event) => { event.stopPropagation(); updateApproval(incident, "rejected"); }} style={{ padding: "4px 8px", fontSize: 11 }}>Reject</Button>
                </div>
              ) : (
                <Link to={`/incidents/${incident.id}`} style={{ display: "flex", justifyContent: "flex-end" }}>
                  <ChevronRight size={15} color="var(--t4)" />
                </Link>
              )
            ) },
          ]}
          rows={sortedRows}
          loading={incidentsQuery.isLoading}
          empty={<EmptyState icon={AlertTriangle} title="No incidents match your filters" subtitle="Adjust the severity, status, or source filters, or create a manual incident." />}
          rowKey={(incident) => incident.id}
          sort={sort}
          onSort={(key) => setSort((current) => nextSort(current, key))}
          pagination
          pageSize={12}
        />
      </div>

      <CreateIncidentModal open={createOpen} onClose={() => setCreateOpen(false)} onSubmit={createIncident} pending={createMutation.isPending} />
    </>
  );
}

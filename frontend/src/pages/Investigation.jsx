import { useEffect, useMemo, useState } from "react";
import {
  CheckSquare,
  Copy,
  Database,
  FileMagnifyingGlass as FileSearch,
  LinkSimple as Link2,
  ListChecks,
  Plus,
  MagnifyingGlass as Search,
  Square,
  X,
} from "@phosphor-icons/react";
import PageHeader from "../components/layout/PageHeader";
import Input, { Textarea } from "../components/ui/Input";
import AppSelect from "../components/ui/AppSelect";
import AppTimeRangePicker, { defaultTimeRange } from "../components/ui/AppTimeRangePicker";
import Button from "../components/ui/Button";
import Modal from "../components/ui/Modal";
import SeverityBadge from "../components/ui/SeverityBadge";
import Tabs from "../components/ui/Tabs";
import EmptyState from "../components/ui/EmptyState";
import Table from "../components/ui/Table";
import { useIntegrations } from "../context/IntegrationContext";
import { nextSort, sortRows } from "../utils/sort";
import {
  useLogChainMutation,
  useRunInvestigationSearch,
  useRunSavedSearches,
  useSplunkReports,
  useSplunkSavedSearches,
  useSyncSplunkCache,
} from "../hooks/queries/useInvestigationQueries";
import {
  incidentListFrom,
  useAddEvidence,
  useBulkAddEvidence,
  useCreateIncident,
  useIncidentsQuery,
} from "../hooks/queries/useIncidentQueries";

const INDEX_OPTIONS = ["*", "web", "pfsense", "windows", "riskops"].map((value) => ({ value, label: value === "*" ? "All indexes" : value }));
const LIMIT_OPTIONS = [50, 100, 250, 500].map((value) => ({ value, label: String(value) }));
const BOOL_OPTIONS = [
  { value: "", label: "Any" },
  { value: "true", label: "Authenticated" },
  { value: "false", label: "Unauthenticated" },
];
const DASH = "-";

const emptySimple = {
  index: "*",
  timeRange: defaultTimeRange(),
  keyword: "",
  source_ip: "",
  destination_ip: "",
  user: "",
  limit: 100,
};

const emptyAdvanced = {
  timeRange: defaultTimeRange(),
  index: "*",
  limit: 100,
  host: "",
  sourcetype: "",
  source: "",
  action: "",
  category: "",
  status_code: "",
  method: "",
  path: "",
  user_agent: "",
  authenticated: "",
  severity: "",
  include_keyword: "",
  exclude_keyword: "",
  source_ip: "",
  destination_ip: "",
  user: "",
};

const emptySpl = {
  spl: "search index=* earliest=-24h latest=now | head 100",
  timeRange: defaultTimeRange(),
  index: "*",
  limit: 100,
};

function fmt(value) {
  if (value === null || value === undefined || value === "") return DASH;
  return String(value);
}

function fmtTime(value) {
  if (!value) return DASH;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toISOString().replace("T", " ").substring(0, 19);
}

function safeJson(value) {
  try {
    return JSON.stringify(value ?? {}, null, 2);
  } catch {
    return String(value ?? "");
  }
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function cell(value, width = 150) {
  return (
    <span
      title={fmt(value)}
      style={{
        display: "inline-block",
        maxWidth: width,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
        verticalAlign: "bottom",
      }}
    >
      {fmt(value)}
    </span>
  );
}

function Banner({ tone = "info", children }) {
  const color = tone === "error" ? "#FCA5A5" : tone === "warn" ? "#FDE68A" : "var(--t2)";
  const border = tone === "error" ? "rgba(220,38,38,0.35)" : tone === "warn" ? "rgba(202,138,4,0.35)" : "rgba(37,99,235,0.25)";
  const bg = tone === "error" ? "rgba(220,38,38,0.10)" : tone === "warn" ? "rgba(202,138,4,0.10)" : "rgba(37,99,235,0.08)";
  return (
    <div style={{ background: bg, border: `1px solid ${border}`, borderRadius: 8, padding: 12, color, fontSize: 13 }}>
      {children}
    </div>
  );
}

function SavedSearchCard({ item, checked, onToggle, kind }) {
  const title = item.title || item.name || "Untitled";
  return (
    <button
      type="button"
      onClick={onToggle}
      style={{
        width: "100%",
        minWidth: 0,
        maxWidth: "100%",
        textAlign: "left",
        background: checked ? "var(--ac-d)" : "var(--s1)",
        border: `1px solid ${checked ? "var(--b3)" : "var(--b0)"}`,
        borderRadius: 8,
        padding: 12,
        color: "var(--t2)",
        cursor: "pointer",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {checked ? <CheckSquare size={15} color="var(--ac-h)" /> : <Square size={15} color="var(--t3)" />}
        <div style={{ color: "var(--t1)", fontWeight: 700, fontSize: 13, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{title}</div>
      </div>
      <div style={{ marginTop: 6, color: "var(--t3)", fontSize: 12 }}>
        {kind === "alert"
          ? `Severity: ${item.severity || "unknown"} | ${item.disabled ? "disabled" : "enabled"} | ${item.cron_schedule || item.alert_type || "triggered by Splunk"}`
          : `${item.cron_schedule || "unscheduled"} | ${item.description || "Splunk saved search"}`}
      </div>
    </button>
  );
}

function EventTable({ events, selectedIds, onToggle, onOpen, loading }) {
  const [sort, setSort] = useState({ key: "time", direction: "desc" });
  const sortedEvents = useMemo(() => sortRows(events, sort, {
    time: (event) => event.time || event._time,
    severity: (event) => event.severity || event.level,
    source_ip: (event) => event.source_ip,
    destination_ip: (event) => event.destination_ip,
    user: (event) => event.email || event.user,
    host: (event) => event.host,
    action: (event) => event.action,
    status_code: (event) => event.status_code || event.error_status,
    index: (event) => event.index,
    message: (event) => event.message || event.matched_saved_search,
  }), [events, sort]);
  return (
    <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", boxShadow: "var(--el-1)", borderRadius: 10, overflow: "hidden", minWidth: 0 }}>
      <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--b0)", display: "flex", justifyContent: "space-between", color: "var(--t3)", fontSize: 12 }}>
        <div>{loading ? "Searching..." : `${events.length} events found`}</div>
        <div>Rows are clickable. Use checkboxes to attach evidence to incidents.</div>
      </div>
      <div className="scrollbar-thin" style={{ maxHeight: "calc(100vh - 430px)", overflow: "auto" }}>
        <Table
          columns={[
            { key: "select", label: "", sortable: false, render: (event) => {
              const id = event.id || `${event.time || event._time || ""}-${event.message || ""}`;
              const checked = selectedIds.has(id);
              return (
                <button onClick={(e) => { e.stopPropagation(); onToggle({ ...event, id }); }} style={iconButtonStyle} title="Select event">
                  {checked ? <CheckSquare size={15} color="var(--ac-h)" /> : <Square size={15} />}
                </button>
              );
            } },
            { key: "time", label: "Time", render: (event) => <span className="mono" style={{ color: "var(--t3)", fontSize: 11 }}>{fmtTime(event.time || event._time)}</span> },
            { key: "severity", label: "Severity", render: (event) => <SeverityBadge severity={event.severity || event.level || "unknown"} /> },
            { key: "source_ip", label: "Source IP", render: (event) => <span className="mono">{cell(event.source_ip, 120)}</span> },
            { key: "destination_ip", label: "Destination IP", render: (event) => <span className="mono">{cell(event.destination_ip, 120)}</span> },
            { key: "user", label: "User", render: (event) => cell(event.email || event.user, 160) },
            { key: "host", label: "Host", render: (event) => cell(event.host, 120) },
            { key: "action", label: "Action", render: (event) => cell(event.action, 140) },
            { key: "status_code", label: "Status", render: (event) => <span className="mono">{fmt(event.status_code || event.error_status)}</span> },
            { key: "index", label: "Index", render: (event) => cell(event.index, 100) },
            { key: "message", label: "Short message", render: (event) => <span style={{ whiteSpace: "normal" }}>{cell(event.message || event.matched_saved_search, 300)}</span> },
          ]}
          rows={sortedEvents}
          loading={loading}
          empty={<EmptyState title="0 events found" subtitle="Run a search, select Splunk alerts, or select reports to investigate related logs." />}
          rowKey={(event, idx) => event.id || `${event.time || idx}-${idx}`}
          onRowClick={(event) => onOpen({ ...event, id: event.id || `${event.time || ""}-${event.message || ""}` })}
          sort={sort}
          onSort={(key) => setSort((cur) => nextSort(cur, key))}
          pagination
          pageSize={25}
        />
      </div>
    </section>
  );
}

function EventDetail({ event, chain, chainLoading, incidentId, onClose, onPivot, onAddOne, onAddChain, onCreate, onOpenChainEvent }) {
  const [rawOpen, setRawOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  if (!event) return null;

  async function copyRaw() {
    await navigator.clipboard.writeText(safeJson(event.raw || event));
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  const chainEvents = safeArray(chain?.events);
  return (
    <Modal open={!!event} onClose={onClose} title="Log Detail" maxWidth={1100}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
        <DetailSection title="Summary" rows={[
          ["Time", fmtTime(event.time || event._time)],
          ["Index", event.index],
          ["Sourcetype", event.sourcetype],
          ["Host", event.host],
          ["Source", event.source],
          ["Severity", event.level || event.severity],
          ["Action", event.action],
          ["Outcome", event.outcome],
          ["Message", event.message],
        ]} />
        <DetailSection title="Network And Identity" rows={[
          ["Source IP", event.source_ip],
          ["Destination IP", event.destination_ip],
          ["Destination port", event.destination_port],
          ["Method", event.method],
          ["Path / URL", event.original_url || event.path],
          ["Status code", event.status_code],
          ["User / email", event.email || event.user],
          ["Authenticated", event.authenticated],
          ["Error", event.error_message || event.error_status_text],
        ]} />
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 14 }}>
        {[
          ["Same source IP", "source_ip", event.source_ip],
          ["Same destination IP", "destination_ip", event.destination_ip],
          ["Same user", "user", event.user || event.email],
          ["Same host", "host", event.host],
          ["Same action", "action", event.action],
        ].filter(([, , value]) => value).map(([label, field, value]) => (
          <Button key={label} variant="secondary" onClick={() => onPivot(field, value)}>{label}</Button>
        ))}
        <Button variant="secondary" disabled={!incidentId} onClick={() => onAddOne(event)}>
          <Link2 size={14} /> Add log
        </Button>
        <Button variant="secondary" disabled={!incidentId || chainEvents.length === 0} onClick={() => onAddChain(chainEvents)}>
          <ListChecks size={14} /> Add chain
        </Button>
        <Button variant="primary" onClick={() => onCreate([event])}>
          <Plus size={14} /> Create incident
        </Button>
      </div>

      <section style={{ ...subCardStyle, marginTop: 14 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <div style={sectionTitleStyle}>Log Chain</div>
          <div style={{ color: "var(--t3)", fontSize: 12 }}>{chainLoading ? "Loading chain..." : `${chainEvents.length} related events`}</div>
        </div>
        {chain?.error && <Banner tone="error">{chain.error}</Banner>}
        <div className="scrollbar-thin" style={{ maxHeight: 260, overflow: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
          {!chainLoading && chainEvents.length === 0 && <div style={{ color: "var(--t3)", fontSize: 13 }}>No related chain found for this event.</div>}
          {chainEvents.map((item, index) => {
            const current = item.id === event.id || (item.time && item.time === event.time && item.message === event.message);
            return (
              <button
                key={item.id || index}
                onClick={() => onOpenChainEvent(item)}
                style={{
                  textAlign: "left",
                  display: "grid",
                  gridTemplateColumns: "160px 150px 170px 80px 1fr",
                  gap: 10,
                  alignItems: "center",
                  padding: "8px 10px",
                  borderRadius: 6,
                  border: `1px solid ${current ? "var(--b3)" : "var(--b0)"}`,
                  background: current ? "var(--ac-d)" : "var(--s1)",
                  color: "var(--t2)",
                  cursor: "pointer",
                  fontSize: 12,
                }}
              >
                <span className="mono" style={{ color: "var(--t3)" }}>{fmtTime(item.time || item._time)}</span>
                <span>{item.action || item.category || "Event"}</span>
                <span className="mono">{fmt(item.source_ip)} -&gt; {fmt(item.destination_ip)}</span>
                <span>{fmt(item.status_code)}</span>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{fmt(item.message || item.path)}</span>
              </button>
            );
          })}
        </div>
      </section>

      <section style={{ ...subCardStyle, marginTop: 14 }}>
        <button onClick={() => setRawOpen((v) => !v)} style={{ ...linkButtonStyle, width: "100%", justifyContent: "space-between" }}>
          <span>Raw event JSON</span>
          <span style={{ color: "var(--t3)" }}>{rawOpen ? "Hide" : "Show"}</span>
        </button>
        {rawOpen && (
          <>
            <div style={{ margin: "10px 0" }}>
              <Button variant="secondary" onClick={copyRaw} style={{ padding: "5px 10px" }}>
                <Copy size={13} /> {copied ? "Copied" : "Copy raw"}
              </Button>
            </div>
            <pre className="mono scrollbar-thin" style={rawStyle}>{safeJson(event.raw || event)}</pre>
          </>
        )}
      </section>
    </Modal>
  );
}

function DetailSection({ title, rows }) {
  return (
    <section style={subCardStyle}>
      <div style={sectionTitleStyle}>{title}</div>
      <div style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: "6px 12px", fontSize: 12 }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: "contents" }}>
            <div style={{ color: "var(--t3)" }}>{label}</div>
            <div style={{ color: "var(--t1)", wordBreak: "break-word" }}>{fmt(value)}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function IncidentModal({ action, incidents, onClose, onCreate, onAdd }) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [incidentId, setIncidentId] = useState("");
  const events = safeArray(action?.events);
  if (!action) return null;

  return (
    <Modal open={!!action} onClose={onClose} title={action.mode === "create" ? "Create Incident" : "Add Evidence"} maxWidth={620}>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ color: "var(--t3)", fontSize: 13 }}>{events.length} log event{events.length === 1 ? "" : "s"} selected</div>
        {action.mode === "create" ? (
          <>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Incident title" />
            <AppSelect value={severity} onChange={setSeverity} options={[
              { value: "critical", label: "Critical" },
              { value: "high", label: "High" },
              { value: "medium", label: "Medium" },
              { value: "low", label: "Low" },
              { value: "informational", label: "Informational" },
            ]} />
            <Button variant="primary" disabled={!title.trim()} onClick={() => onCreate({ title, severity, events })}>
              Create incident
            </Button>
          </>
        ) : (
          <>
            <AppSelect value={incidentId} onChange={setIncidentId} options={[
              { value: "", label: "Select incident" },
              ...incidents.map((incident) => ({ value: incident.id, label: incident.title })),
            ]} />
            <Button variant="primary" disabled={!incidentId} onClick={() => onAdd({ incidentId, events })}>
              Add evidence
            </Button>
          </>
        )}
      </div>
    </Modal>
  );
}

export default function Investigation() {
  const { status } = useIntegrations();
  const [mode, setMode] = useState("simple");
  const [simple, setSimple] = useState(emptySimple);
  const [advanced, setAdvanced] = useState(emptyAdvanced);
  const [splSearch, setSplSearch] = useState(emptySpl);
  const [savedOpen, setSavedOpen] = useState(() => localStorage.getItem("ztx_saved_searches_open") === "true");
  const [savedTab, setSavedTab] = useState("alerts");
  const [savedFilter, setSavedFilter] = useState("");
  const [selectedAlerts, setSelectedAlerts] = useState([]);
  const [selectedReports, setSelectedReports] = useState([]);
  const [activeIncidentId, setActiveIncidentId] = useState("");
  const [events, setEvents] = useState([]);
  const [groups, setGroups] = useState([]);
  const [selectedEvents, setSelectedEvents] = useState(new Map());
  const [detail, setDetail] = useState(null);
  const [chain, setChain] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [query, setQuery] = useState("");
  const [source, setSource] = useState("splunk");
  const [toast, setToast] = useState(null);
  const [incidentAction, setIncidentAction] = useState(null);
  const savedSearchesQuery = useSplunkSavedSearches();
  const reportsQuery = useSplunkReports();
  const incidentsQuery = useIncidentsQuery({});
  const searchMutation = useRunInvestigationSearch();
  const savedSearchMutation = useRunSavedSearches();
  const logChainMutation = useLogChainMutation();
  const cacheMutation = useSyncSplunkCache();
  const createIncidentMutation = useCreateIncident();
  const addEvidenceMutation = useAddEvidence();
  const bulkAddEvidenceMutation = useBulkAddEvidence();

  const splunk = status?.splunk || {};
  const splunkConfigured = !!(splunk.management_configured ?? splunk.configured);
  const savedSearches = safeArray(savedSearchesQuery.data?.items);
  const reportsList = safeArray(reportsQuery.data?.items);
  const incidents = incidentListFrom(incidentsQuery.data || {});
  const incidentLoadError = incidentsQuery.error?.message || incidentsQuery.data?.error || null;
  const savedLoading = savedSearchesQuery.isLoading || reportsQuery.isLoading;
  const chainLoading = logChainMutation.isPending;
  const alerts = useMemo(() => savedSearches.filter((item) => item.type === "alert"), [savedSearches]);
  const reports = useMemo(() => reportsList.length ? reportsList : savedSearches.filter((item) => item.type !== "alert"), [reportsList, savedSearches]);
  const visibleSavedItems = useMemo(() => {
    const term = savedFilter.trim().toLowerCase();
    const list = savedTab === "alerts" ? alerts : reports;
    if (!term) return list;
    return list.filter((item) => [
      item.title,
      item.name,
      item.description,
      item.search,
      item.cron_schedule,
    ].some((value) => String(value || "").toLowerCase().includes(term)));
  }, [alerts, reports, savedFilter, savedTab]);
  const selectedIds = useMemo(() => new Set(selectedEvents.keys()), [selectedEvents]);
  const selectedList = useMemo(() => Array.from(selectedEvents.values()), [selectedEvents]);

  async function loadSavedSearches() {
    await Promise.allSettled([savedSearchesQuery.refetch(), reportsQuery.refetch()]);
  }

  async function loadIncidents() {
    await incidentsQuery.refetch();
  }

  useEffect(() => { document.title = "Investigation — ZeroTrustX"; }, []);
  useEffect(() => {
    setActiveIncidentId((cur) => cur || incidents[0]?.id || "");
  }, [incidents]);

  useEffect(() => {
    if (!detail) {
      setChain(null);
      return;
    }
    loadLogChain(detail);
  }, [detail]);

  function simplePayload(overrides = {}) {
    const merged = { ...simple, ...overrides };
    return {
      mode: "simple",
      timeRange: merged.timeRange,
      index: merged.index,
      limit: Number(merged.limit) || 100,
      filters: {
        keyword: merged.keyword,
        source_ip: merged.source_ip,
        destination_ip: merged.destination_ip,
        user: merged.user,
      },
      selectedAlertIds: selectedAlerts,
      selectedReportIds: selectedReports,
    };
  }

  function advancedPayload() {
    return {
      mode: "advanced",
      timeRange: advanced.timeRange,
      index: advanced.index,
      limit: Number(advanced.limit) || 100,
      filters: advanced,
      selectedAlertIds: selectedAlerts,
      selectedReportIds: selectedReports,
    };
  }

  function splPayload() {
    return {
      mode: "spl",
      spl: splSearch.spl,
      timeRange: splSearch.timeRange,
      index: splSearch.index,
      limit: Number(splSearch.limit) || 100,
      selectedAlertIds: selectedAlerts,
      selectedReportIds: selectedReports,
    };
  }

  async function runSimple(overrides = {}) {
    setLoading(true);
    setError(null);
    setGroups([]);
    try {
      const data = await searchMutation.mutateAsync(simplePayload(overrides)) || {};
      const rows = safeArray(data.events);
      setEvents(rows);
      setGroups(safeArray(data.groups));
      setQuery(data.query || "");
      setSource(data.cacheUsed ? data.source || "cache" : data.source || "splunk");
      setError(data.error || null);
      setSelectedEvents(new Map());
    } catch (e) {
      setEvents([]);
      setError(e?.response?.data?.detail || e?.response?.data?.error || e.message || "Search failed");
    } finally {
      setLoading(false);
    }
  }

  async function runAdvanced() {
    setLoading(true);
    setError(null);
    setGroups([]);
    try {
      const data = await searchMutation.mutateAsync(advancedPayload()) || {};
      setEvents(safeArray(data.events));
      setGroups(safeArray(data.groups));
      setQuery(data.query || "");
      setSource(data.source || "splunk");
      setError(data.error || null);
      setSelectedEvents(new Map());
    } catch (e) {
      setEvents([]);
      setError(e?.response?.data?.detail || e?.response?.data?.error || e.message || "Advanced search failed");
    } finally {
      setLoading(false);
    }
  }

  async function runSpl() {
    setLoading(true);
    setError(null);
    setGroups([]);
    try {
      const data = await searchMutation.mutateAsync(splPayload()) || {};
      setEvents(safeArray(data.events));
      setGroups(safeArray(data.groups));
      setQuery(data.query || splSearch.spl);
      setSource(data.source || "splunk");
      setError(data.error || null);
      setSelectedEvents(new Map());
    } catch (e) {
      setEvents([]);
      setError(e?.response?.data?.detail || e?.response?.data?.error || e.message || "SPL search failed");
    } finally {
      setLoading(false);
    }
  }

  async function runSaved(kind) {
    const alertIds = kind === "reports" ? [] : selectedAlerts;
    const reportIds = kind === "alerts" ? [] : selectedReports;
    setLoading(true);
    setError(null);
    setQuery("");
    try {
      const data = await savedSearchMutation.mutateAsync({
        alertIds,
        reportIds,
        timeRange: simple.timeRange,
        limit: Number(simple.limit) || 100,
      }) || {};
      const nextGroups = safeArray(data.groups);
      setGroups(nextGroups);
      setEvents(nextGroups.flatMap((group) => safeArray(group.events).map((event) => ({ ...event, matched_saved_search: group.savedSearchName }))));
      setSource(data.source || "splunk");
      setError(data.error || null);
      setSelectedEvents(new Map());
    } catch (e) {
      setGroups([]);
      setEvents([]);
      setError(e?.response?.data?.detail || e.message || "Saved search execution failed");
    } finally {
      setLoading(false);
    }
  }

  async function syncCache() {
    setLoading(true);
    setError(null);
    try {
      const data = await cacheMutation.mutateAsync({ timeRange: "Last 24h", limit: 1000 }) || {};
      showToast(data.error ? data.error : `Cached ${data.cached || 0} Splunk events`);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || "Cache sync failed");
    } finally {
      setLoading(false);
    }
  }

  async function loadLogChain(event) {
    setChain(null);
    try {
      const data = await logChainMutation.mutateAsync({ event, windowMinutes: 10, limit: 50 }) || {};
      setChain(data);
    } catch (e) {
      setChain({ events: [], count: 0, error: e?.response?.data?.detail || e.message || "Log chain failed" });
    }
  }

  function toggleEvent(event) {
    const id = event.id || `${event.time || ""}-${event.message || ""}`;
    setSelectedEvents((cur) => {
      const next = new Map(cur);
      if (next.has(id)) next.delete(id);
      else next.set(id, { ...event, id });
      return next;
    });
  }

  function toggleAllVisible() {
    setSelectedEvents((cur) => {
      const next = new Map(cur);
      const allSelected = events.length > 0 && events.every((event, idx) => next.has(event.id || `${event.time || idx}-${idx}`));
      if (allSelected) {
        events.forEach((event, idx) => next.delete(event.id || `${event.time || idx}-${idx}`));
      } else {
        events.forEach((event, idx) => {
          const id = event.id || `${event.time || idx}-${idx}`;
          next.set(id, { ...event, id });
        });
      }
      return next;
    });
  }

  function showToast(message) {
    setToast(message);
    setTimeout(() => setToast(null), 2600);
  }

  async function addEvidence({ incidentId, events: evidenceEvents }) {
    try {
      const data = evidenceEvents.length === 1
        ? await addEvidenceMutation.mutateAsync({ incidentId, event: { event: evidenceEvents[0] } })
        : await bulkAddEvidenceMutation.mutateAsync({ incidentId, events: evidenceEvents });
      showToast(`Added ${data.added || evidenceEvents.length} log${evidenceEvents.length === 1 ? "" : "s"} to incident`);
      setIncidentAction(null);
      setSelectedEvents(new Map());
      await loadIncidents();
    } catch (e) {
      setError(e?.message || "Failed to add evidence");
    }
  }

  async function createIncident({ title, severity, events: evidenceEvents }) {
    try {
      const data = await createIncidentMutation.mutateAsync({
        title,
        severity,
        status: evidenceEvents.length ? "new" : "pending_evidence",
        category: "other",
        description: `Created from ${evidenceEvents.length} investigation log${evidenceEvents.length === 1 ? "" : "s"}.`,
        source: "analyst",
        detection_source: "investigation",
        evidence: evidenceEvents,
      });
      showToast("Incident created");
      setIncidentAction(null);
      setSelectedEvents(new Map());
      await loadIncidents();
      if (data.incident?.id) setActiveIncidentId(data.incident.id);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || "Failed to create incident");
    }
  }

  function pivot(field, value) {
    setDetail(null);
    setMode("simple");
    setSimple((cur) => ({ ...cur, [field]: value }));
    runSimple({ [field]: value });
  }

  function toggleSaved(id, setter) {
    setter((cur) => cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]);
  }

  return (
    <>
      <PageHeader title="Investigation" subtitle="Search Splunk, inspect log chains, and attach evidence to incidents" />
      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20, minWidth: 0 }}>
        {!splunkConfigured && <Banner tone="warn"><Database size={14} /> Splunk Management API is not configured. DB and Redis are not required for this page.</Banner>}
        {incidentLoadError && <Banner tone="warn">{incidentLoadError}</Banner>}
        {toast && <Banner>{toast}</Banner>}

        <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", boxShadow: "var(--el-1)", borderRadius: 10, padding: 16, overflow: "visible" }}>
          <Tabs
            value={mode}
            onChange={setMode}
            tabs={[
              { label: "Simple Search", value: "simple" },
              { label: "Advanced Search", value: "advanced" },
              { label: "SPL Search", value: "spl" },
            ]}
          />

          {mode === "simple" ? (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
              <Field label="Time range"><AppTimeRangePicker value={simple.timeRange} onChange={(timeRange) => setSimple({ ...simple, timeRange })} /></Field>
              <Field label="Index"><AppSelect value={simple.index} onChange={(index) => setSimple({ ...simple, index })} options={INDEX_OPTIONS} /></Field>
              <Field label="Keyword"><Input value={simple.keyword} onChange={(e) => setSimple({ ...simple, keyword: e.target.value })} /></Field>
              <Field label="Limit"><AppSelect value={simple.limit} onChange={(limit) => setSimple({ ...simple, limit: Number(limit) })} options={LIMIT_OPTIONS} /></Field>
              {[
                ["source_ip", "Source IP"],
                ["destination_ip", "Destination IP"],
                ["user", "User / Email"],
              ].map(([key, label]) => (
                <Field key={key} label={label}><Input value={simple[key]} onChange={(e) => setSimple({ ...simple, [key]: e.target.value })} /></Field>
              ))}
              <div style={{ display: "flex", alignItems: "flex-end", gap: 8 }}>
                <Button variant="primary" onClick={() => runSimple()} disabled={loading}><Search size={14} /> Search</Button>
                <Button variant="ghost" onClick={() => setSimple(emptySimple)}><X size={14} /> Reset</Button>
              </div>
            </div>
          ) : mode === "advanced" ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
                <Field label="Time range"><AppTimeRangePicker value={advanced.timeRange} onChange={(timeRange) => setAdvanced({ ...advanced, timeRange })} /></Field>
                <Field label="Index"><AppSelect value={advanced.index} onChange={(index) => setAdvanced({ ...advanced, index })} options={INDEX_OPTIONS} /></Field>
                <Field label="Limit"><AppSelect value={advanced.limit} onChange={(limit) => setAdvanced({ ...advanced, limit: Number(limit) })} options={LIMIT_OPTIONS} /></Field>
                <Field label="Severity / level"><Input value={advanced.severity} onChange={(e) => setAdvanced({ ...advanced, severity: e.target.value })} /></Field>
                {[
                  ["source_ip", "Source IP"],
                  ["destination_ip", "Destination IP"],
                  ["user", "User / Email"],
                  ["host", "Host"],
                  ["sourcetype", "Sourcetype"],
                  ["source", "Source"],
                  ["action", "Action"],
                  ["category", "Event category"],
                  ["status_code", "Status code"],
                  ["method", "HTTP method"],
                  ["path", "Path / URL"],
                  ["user_agent", "User agent"],
                  ["include_keyword", "Include keyword"],
                  ["exclude_keyword", "Exclude keyword"],
                ].map(([key, label]) => (
                  <Field key={key} label={label}><Input value={advanced[key]} onChange={(e) => setAdvanced({ ...advanced, [key]: e.target.value })} /></Field>
                ))}
                <Field label="Authenticated"><AppSelect value={advanced.authenticated} onChange={(authenticated) => setAdvanced({ ...advanced, authenticated })} options={BOOL_OPTIONS} /></Field>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <Button variant="primary" onClick={runAdvanced} disabled={loading}><Search size={14} /> Search</Button>
                <Button variant="ghost" onClick={() => setAdvanced(emptyAdvanced)}><X size={14} /> Reset</Button>
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <Textarea value={splSearch.spl} onChange={(e) => setSplSearch({ ...splSearch, spl: e.target.value })} style={{ minHeight: 118, fontFamily: "var(--font-mono)", fontSize: 12 }} />
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, alignItems: "end" }}>
                <Field label="Time range"><AppTimeRangePicker value={splSearch.timeRange} onChange={(timeRange) => setSplSearch({ ...splSearch, timeRange })} /></Field>
                <Field label="Index override"><AppSelect value={splSearch.index} onChange={(index) => setSplSearch({ ...splSearch, index })} options={INDEX_OPTIONS} /></Field>
                <Field label="Limit"><AppSelect value={splSearch.limit} onChange={(limit) => setSplSearch({ ...splSearch, limit: Number(limit) })} options={LIMIT_OPTIONS} /></Field>
                <div style={{ display: "flex", gap: 8 }}>
                  <Button variant="primary" onClick={runSpl} disabled={loading}><Search size={14} /> Run SPL</Button>
                </div>
              </div>
              <Banner tone="warn">SPL Search is for analysts who need full Splunk syntax. It runs only through the backend; delete, outputlookup, collect, script, sendemail, map, and rest are blocked.</Banner>
              <div className="mono" style={{ color: "var(--t3)", fontSize: 11 }}>Preview: {splSearch.spl || "search index=* earliest=-24h latest=now | head 100"}</div>
            </div>
          )}
        </section>

        <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", boxShadow: "var(--el-1)", borderRadius: 10, padding: 16, width: "100%", maxWidth: "100%", overflow: "visible" }}>
          <button
            type="button"
            onClick={() => {
              const next = !savedOpen;
              setSavedOpen(next);
              localStorage.setItem("ztx_saved_searches_open", String(next));
            }}
            style={{
              width: "100%",
              display: "flex",
              justifyContent: "space-between",
              gap: 12,
              alignItems: "center",
              background: "transparent",
              border: "none",
              color: "var(--t1)",
              padding: 0,
              cursor: "pointer",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--t1)", fontWeight: 700 }}>
              <FileSearch size={15} color="var(--ac-h)" /> Splunk Alerts And Reports
            </div>
            <div style={{ color: "var(--t3)", fontSize: 12 }}>
              {selectedAlerts.length} alerts selected · {selectedReports.length} reports selected · {savedOpen ? "Collapse" : "Expand"}
            </div>
          </button>
          {savedOpen && (
            <div style={{ marginTop: 12, minWidth: 0, display: "grid", gap: 10 }}>
              {savedLoading ? (
                <div style={{ color: "var(--t3)", fontSize: 13 }}>Loading Splunk saved searches...</div>
              ) : (
                <>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                    <Tabs
                      value={savedTab}
                      onChange={setSavedTab}
                      tabs={[
                        { label: `Alerts (${alerts.length})`, value: "alerts" },
                        { label: `Reports (${reports.length})`, value: "reports" },
                      ]}
                    />
                    <Input value={savedFilter} onChange={(e) => setSavedFilter(e.target.value)} placeholder="Filter alerts or reports" style={{ maxWidth: 260 }} />
                  </div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {selectedAlerts.map((id) => <Chip key={`a-${id}`} label={`Alert ${shortId(id)}`} onRemove={() => toggleSaved(id, setSelectedAlerts)} />)}
                    {selectedReports.map((id) => <Chip key={`r-${id}`} label={`Report ${shortId(id)}`} onRemove={() => toggleSaved(id, setSelectedReports)} />)}
                  </div>
                  <SavedSearchList
                    title={savedTab === "alerts" ? "Splunk Alerts" : "Splunk Reports"}
                    empty={savedTab === "alerts" ? "No Splunk alerts found." : "No Splunk reports found."}
                    items={visibleSavedItems}
                    selected={savedTab === "alerts" ? selectedAlerts : selectedReports}
                    onToggle={(id) => toggleSaved(id, savedTab === "alerts" ? setSelectedAlerts : setSelectedReports)}
                    kind={savedTab === "alerts" ? "alert" : "report"}
                  />
                </>
              )}
              <div style={{ color: "var(--t3)", fontSize: 12, marginTop: 10 }}>
                Selected alerts and reports are included when you click the main Search button above.
              </div>
            </div>
          )}
        </section>

        {error && <Banner tone="error">{String(error)}</Banner>}
        {query && <div className="mono" style={{ background: "var(--s1)", border: "1px solid var(--b0)", borderRadius: 8, padding: "8px 12px", color: "var(--t3)", fontSize: 11, overflowWrap: "anywhere", whiteSpace: "pre-wrap" }}>{query}</div>}
        {groups.length > 0 && (
          <div style={{ background: "var(--s1)", border: "1px solid var(--b0)", borderRadius: 8, padding: 12, display: "flex", gap: 12, flexWrap: "wrap" }}>
            {groups.map((g) => <span key={g.savedSearchName} style={{ fontSize: 12, color: g.error ? "var(--crit)" : "var(--t2)" }}>{g.savedSearchName}: <span className="mono">{g.count}</span>{g.error ? ` (${g.error})` : ""}</span>)}
          </div>
        )}

        <EvidenceBar
          selected={selectedList}
          incidents={incidents}
          activeIncidentId={activeIncidentId}
          setActiveIncidentId={setActiveIncidentId}
          source={source}
          onAdd={() => setIncidentAction({ mode: "add", events: selectedList })}
          onCreate={() => setIncidentAction({ mode: "create", events: selectedList })}
          onClear={() => setSelectedEvents(new Map())}
          onSync={syncCache}
        />

        <EventTable events={events} selectedIds={selectedIds} onToggle={toggleEvent} onOpen={setDetail} loading={loading} />
      </div>

      <EventDetail
        event={detail}
        chain={chain}
        chainLoading={chainLoading}
        incidentId={activeIncidentId}
        onClose={() => setDetail(null)}
        onPivot={pivot}
        onAddOne={(event) => addEvidence({ incidentId: activeIncidentId, events: [event] })}
        onAddChain={(chainEvents) => addEvidence({ incidentId: activeIncidentId, events: chainEvents })}
        onCreate={(evidenceEvents) => setIncidentAction({ mode: "create", events: evidenceEvents })}
        onOpenChainEvent={setDetail}
      />

      <IncidentModal
        action={incidentAction}
        incidents={incidents}
        onClose={() => setIncidentAction(null)}
        onCreate={createIncident}
        onAdd={addEvidence}
      />
    </>
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

function shortId(value) {
  return String(value || "").slice(0, 18) || "selected";
}

function Chip({ label, onRemove }) {
  return (
    <button
      type="button"
      onClick={onRemove}
      title="Remove selection"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        border: "1px solid var(--b0)",
        background: "rgba(37,99,235,0.10)",
        color: "var(--t2)",
        borderRadius: 999,
        padding: "3px 8px",
        fontSize: 11,
        cursor: "pointer",
      }}
    >
      {label}
      <X size={11} />
    </button>
  );
}

function SavedSearchList({ title, empty, items, selected, onToggle, kind }) {
  return (
    <div className="investigation-saved-column" style={{ ...subCardStyle, minWidth: 0 }}>
      <div style={{ ...sectionTitleStyle, marginBottom: 10 }}>{title}</div>
      <div className="scrollbar-thin investigation-saved-list" style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 0 }}>
        {items.length === 0 ? <div style={{ color: "var(--t3)", fontSize: 13 }}>{empty}</div> : items.map((item) => (
          <SavedSearchCard key={item.id || item.name} item={item} checked={selected.includes(item.id)} onToggle={() => onToggle(item.id)} kind={kind} />
        ))}
      </div>
    </div>
  );
}

function EvidenceBar({ selected, incidents, activeIncidentId, setActiveIncidentId, source, onAdd, onCreate, onClear, onSync }) {
  return (
    <div style={{ background: "var(--s1)", border: "1px solid var(--b0)", borderRadius: 8, padding: 12, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
      <div style={{ color: "var(--t2)", fontSize: 13 }}><span className="mono">{selected.length}</span> selected</div>
      <AppSelect value={activeIncidentId} onChange={setActiveIncidentId} style={{ width: 260 }} options={[
        { value: "", label: "Select incident" },
        ...incidents.map((incident) => ({ value: incident.id, label: incident.title })),
      ]} />
      <Button variant="secondary" disabled={!selected.length || !activeIncidentId} onClick={onAdd}><Link2 size={14} /> Add to incident</Button>
      <Button variant="secondary" disabled={!selected.length} onClick={onCreate}><Plus size={14} /> Create from logs</Button>
      <Button variant="ghost" disabled={!selected.length} onClick={onClear}>Clear selection</Button>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ color: "var(--t3)", fontSize: 12 }}>Source: <span style={{ color: source === "cache" ? "var(--low)" : "var(--t2)" }}>{source}</span></span>
        <Button variant="secondary" onClick={onSync}><Database size={14} /> Sync recent logs</Button>
      </div>
    </div>
  );
}

const thStyle = {
  background: "var(--s1)",
  borderBottom: "1px solid var(--b0)",
  color: "var(--t3)",
  textAlign: "left",
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  padding: "9px 10px",
  minWidth: 0,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

const tdStyle = {
  padding: "9px 10px",
  fontSize: 12,
  color: "var(--t2)",
  verticalAlign: "middle",
  minWidth: 0,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

const iconButtonStyle = {
  background: "transparent",
  border: "none",
  color: "var(--t2)",
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  padding: 2,
};

const sortButtonStyle = {
  display: "inline-flex",
  alignItems: "center",
  gap: 5,
  maxWidth: "100%",
  border: "none",
  background: "transparent",
  color: "inherit",
  padding: 0,
  cursor: "pointer",
  font: "inherit",
  textTransform: "inherit",
  letterSpacing: "inherit",
};

const subCardStyle = {
  background: "var(--s1)",
  border: "1px solid var(--b0)",
  borderRadius: 8,
  padding: 12,
};

const sectionTitleStyle = {
  fontSize: 11,
  color: "var(--t3)",
  textTransform: "uppercase",
  letterSpacing: "0.07em",
  fontWeight: 700,
};

const linkButtonStyle = {
  background: "transparent",
  border: "none",
  color: "var(--t1)",
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  fontSize: 12,
  fontWeight: 700,
  padding: 0,
};

const rawStyle = {
  margin: 0,
  padding: 12,
  maxHeight: 360,
  overflow: "auto",
  background: "rgba(6,10,18,0.65)",
  color: "var(--t2)",
  fontSize: 11,
  whiteSpace: "pre-wrap",
};

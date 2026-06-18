import { useEffect, useMemo, useState } from "react";
import { Download, ArrowSquareOut as ExternalLink, Play, ArrowClockwise as RefreshCw, MagnifyingGlass as Search } from "@phosphor-icons/react";
import { useDashboard } from "../hooks/useDashboard";
import { useDownloadExecutivePdf, useReports, useRunSplunkReport } from "../hooks/queries/useReportQueries";
import PageHeader from "../components/layout/PageHeader";
import Button from "../components/ui/Button";
import Input from "../components/ui/Input";
import AppSelect from "../components/ui/AppSelect";
import Table from "../components/ui/Table";
import Modal from "../components/ui/Modal";
import EmptyState from "../components/ui/EmptyState";
import { getApiError } from "../api/client";
import { nextSort, sortRows } from "../utils/sort";

const RANGE_OPTIONS = [
  { value: "Last 24h", label: "Last 24 hours" },
  { value: "Last 7d", label: "Last 7 days" },
  { value: "Last 30d", label: "Last 30 days" },
  { value: "Last 90d", label: "Last 90 days" },
  { value: "All time", label: "All time" },
];

function fmt(value) {
  if (!value) return "-";
  return String(value);
}

function reportTitle(report) {
  return report?.title || report?.name || "Splunk report";
}

function Badge({ children, tone = "info" }) {
  const color = tone === "ok" ? "var(--low)" : tone === "warn" ? "var(--med)" : "var(--ac-h)";
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      padding: "2px 7px",
      borderRadius: 4,
      border: `1px solid ${color}40`,
      background: `${color}1F`,
      color,
      fontSize: 11,
      textTransform: "uppercase",
      letterSpacing: "0.06em",
    }}>
      {children}
    </span>
  );
}

function Banner({ tone = "info", children }) {
  const isError = tone === "error";
  return (
    <div style={{
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

function CIASummary({ cia }) {
  if (!cia) return null;
  const bars = [
    { key: "c", label: "Confidentiality", color: "#6366F1", value: cia.c ?? 0 },
    { key: "i", label: "Integrity", color: "#EA580C", value: cia.i ?? 0 },
    { key: "a", label: "Availability", color: "#CA8A04", value: cia.a ?? 0 },
  ];
  const max = Math.max(...bars.map((b) => b.value), 1);
  return (
    <div style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: "14px 16px", display: "flex", flexDirection: "column", gap: 10 }}>
      <div style={{ fontSize: 11, color: "var(--t3)", textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 600, marginBottom: 2 }}>
        CIA Risk Score
      </div>
      {bars.map((bar) => (
        <div key={bar.key} style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 110, fontSize: 12, color: "var(--t2)", flexShrink: 0 }}>{bar.label}</div>
          <div style={{ flex: 1, height: 6, borderRadius: 3, background: "var(--s1)", border: "1px solid var(--b0)", overflow: "hidden" }}>
            <div style={{
              height: "100%",
              borderRadius: 3,
              background: bar.color,
              width: `${(bar.value / max) * 100}%`,
              transition: "width var(--dur-slow) var(--ease-out)",
            }} />
          </div>
          <div style={{ width: 36, textAlign: "right", fontFamily: "var(--font-mono)", fontSize: 12, color: bar.color, fontWeight: 600 }}>
            {bar.value}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function Reports() {
  const { data: dashData } = useDashboard(60000);
  const reportsQuery = useReports();
  const runReportMutation = useRunSplunkReport();
  const pdfMutation = useDownloadExecutivePdf();
  const [search, setSearch] = useState("");
  const [range, setRange] = useState("Last 24h");
  const [selected, setSelected] = useState(null);
  const [runResult, setRunResult] = useState(null);
  const [localError, setLocalError] = useState(null);
  const [sort, setSort] = useState({ key: "name", direction: "asc" });

  useEffect(() => { document.title = "Reports - ZeroTrustX"; }, []);

  const reportsData = reportsQuery.data || {};
  const reports = Array.isArray(reportsData.items) ? reportsData.items : [];
  const loading = reportsQuery.isLoading;
  const error = localError || reportsQuery.error?.message || reportsData.error || null;

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    const rows = term ? reports.filter((report) => [
      reportTitle(report),
      report.description,
      report.search,
      report.cron_schedule,
    ].some((value) => String(value || "").toLowerCase().includes(term))) : reports;
    return sortRows(rows, sort, {
      name: (report) => reportTitle(report),
      schedule: (report) => report.cron_schedule || (report.is_scheduled ? "scheduled" : "unscheduled"),
      status: (report) => report.disabled ? "disabled" : "enabled",
      last: (report) => report.last_triggered,
      source: () => "splunk",
    });
  }, [reports, search, sort]);

  async function runReport(report) {
    setSelected(report);
    setRunResult(null);
    setLocalError(null);
    try {
      const data = await runReportMutation.mutateAsync({
        reportIds: [report.id || report.name || report.title],
        timeRange: range,
        limit: 100,
      });
      setRunResult(data || {});
    } catch (e) {
      setRunResult({ groups: [], totalCount: 0, error: getApiError(e, "Report run failed") });
    }
  }

  async function downloadPdf() {
    setLocalError(null);
    try {
      const blob = await pdfMutation.mutateAsync(30);
      const url = URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "zerotrustx-report.pdf";
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setLocalError(getApiError(e, "PDF generation failed"));
    }
  }

  const groups = Array.isArray(runResult?.groups) ? runResult.groups : [];
  const previewEvents = groups.flatMap((group) => (
    Array.isArray(group.events) ? group.events.map((event) => ({ ...event, group: group.savedSearchName })) : []
  ));

  return (
    <>
      <PageHeader
        title="Reports"
        subtitle="Splunk saved reports and scheduled searches"
        actions={
          <>
            <Button variant="secondary" onClick={() => reportsQuery.refetch()} disabled={loading || reportsQuery.isFetching}>
              <RefreshCw size={14} /> {reportsQuery.isFetching ? "Loading" : "Refresh"}
            </Button>
            <Button variant="primary" onClick={downloadPdf} disabled={pdfMutation.isPending}>
              <Download size={14} /> {pdfMutation.isPending ? "Generating" : "Export PDF"}
            </Button>
          </>
        }
      />

      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
        {error && <Banner tone="error">{error}</Banner>}

        {dashData?.cia_scores && <CIASummary cia={dashData.cia_scores} />}

        <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: 14, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, minWidth: 0 }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <span style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>Search reports</span>
            <div style={{ position: "relative" }}>
              <Search size={15} style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--t3)" }} />
              <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Name, description, SPL..." style={{ paddingLeft: 32 }} />
            </div>
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            <span style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>Run time range</span>
            <AppSelect value={range} onChange={setRange} options={RANGE_OPTIONS} />
          </label>
        </section>

        <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: 16 }}>
          <Table
            columns={[
              { key: "name", label: "Report name", render: (r) => (
                <button onClick={() => setSelected(r)} style={{ color: "var(--t1)", fontWeight: 700, background: "transparent", border: "none", padding: 0, cursor: "pointer", textAlign: "left" }}>
                  {reportTitle(r)}
                </button>
              ) },
              { key: "description", label: "Description", render: (r) => (
                <span style={{ color: "var(--t2)", maxWidth: 420, display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{fmt(r.description)}</span>
              ) },
              { key: "schedule", label: "Schedule", render: (r) => r.is_scheduled ? <span className="mono">{fmt(r.cron_schedule)}</span> : "Unscheduled" },
              { key: "status", label: "Status", render: (r) => r.disabled ? <Badge tone="warn">Disabled</Badge> : <Badge tone="ok">Enabled</Badge> },
              { key: "last", label: "Last run", render: (r) => <span className="mono">{fmt(r.last_triggered)}</span> },
              { key: "source", label: "Source", render: () => <Badge>Splunk</Badge> },
              { key: "actions", label: "", render: (r) => (
                <div style={{ display: "flex", gap: 8 }}>
                  <Button variant="secondary" onClick={() => runReport(r)} style={{ padding: "5px 9px" }}><Play size={13} /> Run</Button>
                  <Button variant="ghost" onClick={() => setSelected(r)} style={{ padding: "5px 9px" }}>Details</Button>
                </div>
              ), sortable: false },
            ]}
            rows={filtered}
            rowKey={(r, i) => r.id || r.name || i}
            empty={<EmptyState title="No reports found" subtitle="Create saved searches or reports in Splunk, or use Investigation search." />}
            loading={loading}
            error={reportsQuery.error?.message || null}
            sort={sort}
            onSort={(key) => setSort((cur) => nextSort(cur, key))}
            pagination
            pageSize={10}
          />
        </section>
      </div>

      <Modal open={!!selected} onClose={() => { setSelected(null); setRunResult(null); }} title={selected ? reportTitle(selected) : "Report"} maxWidth={900}>
        {selected && (
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10 }}>
              <Mini label="Source" value="Splunk" />
              <Mini label="Status" value={selected.disabled ? "Disabled" : "Enabled"} />
              <Mini label="Schedule" value={selected.is_scheduled ? selected.cron_schedule : "Unscheduled"} />
              <Mini label="Last run" value={selected.last_triggered || "-"} />
            </div>
            <div>
              <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>SPL query</div>
              <pre className="mono scrollbar-thin" style={{ margin: 0, maxHeight: 170, overflow: "auto", whiteSpace: "pre-wrap", color: "var(--t2)", background: "var(--s1)", border: "1px solid var(--b0)", borderRadius: 8, padding: 12 }}>
                {selected.search || "No SPL query returned by Splunk."}
              </pre>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <Button variant="primary" onClick={() => runReport(selected)} disabled={runReportMutation.isPending}><Play size={14} /> {runReportMutation.isPending ? "Running" : "Run report"}</Button>
              <Button variant="ghost" onClick={() => window.location.assign("/investigation")}><ExternalLink size={14} /> Open Investigation</Button>
            </div>
            {runResult?.error && <Banner tone="error">{runResult.error}</Banner>}
            {runResult && !runResult.error && <Banner>{runResult.totalCount || previewEvents.length || 0} events returned from Splunk.</Banner>}
            {previewEvents.length > 0 && (
              <Table
                columns={[
                  { key: "time", label: "Time", render: (r) => <span className="mono">{fmt(r.time || r._time)}</span> },
                  { key: "source_ip", label: "Source IP", render: (r) => <span className="mono">{fmt(r.source_ip)}</span> },
                  { key: "destination_ip", label: "Destination IP", render: (r) => <span className="mono">{fmt(r.destination_ip)}</span> },
                  { key: "user", label: "User", render: (r) => fmt(r.user || r.email) },
                  { key: "action", label: "Action", render: (r) => fmt(r.action) },
                  { key: "message", label: "Message", render: (r) => <span style={{ display: "block", maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{fmt(r.message)}</span> },
                ]}
                rows={previewEvents}
                rowKey={(r, i) => r.id || r.event_hash || i}
                empty="No results"
                pagination
                pageSize={8}
              />
            )}
          </div>
        )}
      </Modal>
    </>
  );
}

function Mini({ label, value }) {
  return (
    <div style={{ background: "var(--s1)", border: "1px solid var(--b1)", borderRadius: "var(--r-md)", padding: 10, minWidth: 0 }}>
      <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div style={{ color: "var(--t1)", fontSize: 13, marginTop: 5, overflow: "hidden", textOverflow: "ellipsis" }} title={String(value || "")}>{fmt(value)}</div>
    </div>
  );
}

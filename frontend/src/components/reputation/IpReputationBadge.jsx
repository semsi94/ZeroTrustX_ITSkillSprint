import { useState } from "react";
import { ShieldWarning, X } from "@phosphor-icons/react";
import Modal from "../ui/Modal";
import Button from "../ui/Button";
import Tooltip from "../ui/Tooltip";
import { useIpReputation, useRefreshIpReputation, useReputationObservations } from "../../hooks/queries/useReputationQueries";

const COLORS = {
  malicious: ["#FCA5A5", "rgba(220,38,38,0.14)", "rgba(220,38,38,0.45)"],
  suspicious: ["#FDE68A", "rgba(202,138,4,0.16)", "rgba(202,138,4,0.45)"],
  clean: ["#86EFAC", "rgba(22,163,74,0.14)", "rgba(22,163,74,0.45)"],
  error: ["#CBD5E1", "rgba(148,163,184,0.12)", "rgba(148,163,184,0.32)"],
  unknown: ["var(--t3)", "var(--s1)", "var(--b0)"],
};

export default function IpReputationBadge({ ip, reputation, canRefresh = false }) {
  const [open, setOpen] = useState(false);
  const query = useIpReputation(ip, { enabled: open && Boolean(ip) && !reputation });
  const data = reputation || query.data?.reputation || null;
  const verdict = data?.overall_verdict || "unknown";
  const [color, bg, border] = COLORS[verdict] || COLORS.unknown;
  const label = data ? `${verdict} ${data.overall_score ?? 0}` : "Not checked";

  if (!ip || ip === "-") return null;

  return (
    <>
      <Tooltip content={`${ip}: ${label}`}>
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            setOpen(true);
          }}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
            border: `1px solid ${border}`,
            background: bg,
            color,
            borderRadius: 999,
            padding: "2px 7px",
            fontSize: 10,
            cursor: "pointer",
            whiteSpace: "nowrap",
          }}
        >
          <ShieldWarning size={12} /> {label}
        </button>
      </Tooltip>
      <IpReputationModal open={open} onClose={() => setOpen(false)} ip={ip} reputation={data} loading={query.isLoading} error={query.error?.message} canRefresh={canRefresh} />
    </>
  );
}

function IpReputationModal({ open, onClose, ip, reputation, loading, error, canRefresh }) {
  const observationsQuery = useReputationObservations(ip, { enabled: open && Boolean(ip) });
  const refreshMutation = useRefreshIpReputation();
  const provider = reputation?.provider_sources || {};

  return (
    <Modal open={open} onClose={onClose} title={`IP Reputation - ${ip}`} maxWidth={720}>
      <div style={{ display: "grid", gap: 14 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
          <div>
            <div style={{ color: "var(--t1)", fontWeight: 850, fontSize: 18 }}>{reputation?.overall_verdict || (loading ? "Checking" : "Not checked")}</div>
            <div style={{ color: "var(--t3)", fontSize: 12, marginTop: 3 }}>
              Score {reputation?.overall_score ?? 0} - last checked {reputation?.last_checked_at || "never"}
            </div>
          </div>
          {canRefresh && (
            <Button variant="secondary" onClick={() => refreshMutation.mutate({ ip })} disabled={refreshMutation.isPending}>
              {refreshMutation.isPending ? "Refreshing" : "Refresh"}
            </Button>
          )}
        </div>
        {error && <div style={{ color: "var(--crit)", fontSize: 13 }}>{error}</div>}
        {!reputation && !loading && <div style={{ color: "var(--t3)", fontSize: 13 }}>No cached reputation yet. Enrichment will appear after the background job completes.</div>}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 12 }}>
          <ProviderBox title="AbuseIPDB" rows={[
            ["Score", reputation?.abuseipdb_score ?? provider.abuseipdb?.score ?? "-"],
            ["Reports", reputation?.abuseipdb_total_reports ?? provider.abuseipdb?.total_reports ?? "-"],
            ["Country", reputation?.abuseipdb_country_code || "-"],
            ["ISP", reputation?.abuseipdb_isp || "-"],
          ]} />
          <ProviderBox title="VirusTotal" rows={[
            ["Malicious", reputation?.virustotal_malicious ?? provider.virustotal?.malicious ?? "-"],
            ["Suspicious", reputation?.virustotal_suspicious ?? provider.virustotal?.suspicious ?? "-"],
            ["Harmless", reputation?.virustotal_harmless ?? provider.virustotal?.harmless ?? "-"],
            ["AS owner", reputation?.virustotal_as_owner || "-"],
          ]} />
        </div>
        <div>
          <div style={{ color: "var(--t2)", fontWeight: 800, marginBottom: 8 }}>Observations</div>
          {observationsQuery.isLoading ? (
            <div className="skeleton" style={{ height: 38 }} />
          ) : (observationsQuery.data?.observations || []).length ? (
            <div style={{ display: "grid", gap: 8 }}>
              {(observationsQuery.data?.observations || []).slice(0, 8).map((item) => (
                <div key={item.id} style={{ border: "1px solid var(--b0)", borderRadius: 8, padding: 9, color: "var(--t2)", fontSize: 12 }}>
                  {item.source_system} - {item.incident_title || item.incident_id || "unlinked"} - seen {item.occurrence_count} time(s)
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: "var(--t3)", fontSize: 13 }}>No observations recorded yet.</div>
          )}
        </div>
        <button type="button" onClick={onClose} style={{ justifySelf: "end", background: "transparent", border: "none", color: "var(--t3)", cursor: "pointer" }}>
          <X size={14} /> Close
        </button>
      </div>
    </Modal>
  );
}

function ProviderBox({ title, rows }) {
  return (
    <div style={{ border: "1px solid var(--b0)", borderRadius: 10, padding: 12, background: "var(--s1)" }}>
      <div style={{ color: "var(--t1)", fontWeight: 800, marginBottom: 8 }}>{title}</div>
      <div style={{ display: "grid", gap: 6 }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: "flex", justifyContent: "space-between", gap: 10, color: "var(--t2)", fontSize: 12 }}>
            <span style={{ color: "var(--t3)" }}>{label}</span>
            <span className="mono">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus } from "@phosphor-icons/react";
import PageHeader from "../../components/layout/PageHeader";
import Input, { Select } from "../../components/ui/Input";
import Button from "../../components/ui/Button";
import Table from "../../components/ui/Table";
import Modal from "../../components/ui/Modal";
import ZoneBadge from "../../components/ui/ZoneBadge";
import { useAssetsQuery, useCreateAsset } from "../../hooks/queries/useAssetQueries";

const ZONES = [
  { label: "All", value: "" },
  { label: "DMZ", value: "dmz" },
  { label: "Internal", value: "internal" },
  { label: "Management", value: "management" },
];

function CritDots({ n }) {
  const dots = [];
  for (let i = 1; i <= 5; i++) {
    dots.push(
      <span key={i} style={{
        width: 6, height: 6, borderRadius: 3,
        background: i <= n ? "var(--ac-h)" : "var(--b0)",
        display: "inline-block",
      }} />,
    );
  }
  return <span style={{ display: "inline-flex", gap: 3, alignItems: "center" }}>
    {dots}
    <span style={{ fontSize: 11, color: "var(--t3)", marginLeft: 6 }}>{n}/5</span>
  </span>;
}

function FieldLabel({ children }) {
  return (
    <div style={{ fontSize: 11, color: "var(--t3)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>
      {children}
    </div>
  );
}

function AddAssetModal({ open, onClose }) {
  const createAssetMutation = useCreateAsset();
  const [hostname, setHostname] = useState("");
  const [ip, setIp] = useState("");
  const [zone, setZone] = useState("internal");
  const [owner, setOwner] = useState("");
  const [crit, setCrit] = useState(3);
  const [err, setErr] = useState(null);

  useEffect(() => {
    if (!open) return;
    setHostname("");
    setIp("");
    setZone("internal");
    setOwner("");
    setCrit(3);
    setErr(null);
  }, [open]);

  async function submit() {
    setErr(null);
    try {
      await createAssetMutation.mutateAsync({
        hostname,
        ip,
        zone,
        owner,
        asset_criticality: parseInt(crit, 10),
      });
      onClose();
    } catch (e) {
      setErr(e?.message || "Failed to create asset");
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Add Asset" maxWidth={460}>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div>
          <FieldLabel>Hostname</FieldLabel>
          <Input value={hostname} onChange={(e) => setHostname(e.target.value)} />
        </div>
        <div>
          <FieldLabel>IP</FieldLabel>
          <Input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.0.0.1" />
        </div>
        <div>
          <FieldLabel>Zone</FieldLabel>
          <Select value={zone} onChange={(e) => setZone(e.target.value)}>
            <option value="dmz">DMZ</option>
            <option value="internal">Internal</option>
            <option value="management">Management</option>
          </Select>
        </div>
        <div>
          <FieldLabel>Owner</FieldLabel>
          <Input value={owner} onChange={(e) => setOwner(e.target.value)} />
        </div>
        <div>
          <FieldLabel>Criticality</FieldLabel>
          <Select value={crit} onChange={(e) => setCrit(e.target.value)}>
            {[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n}/5</option>)}
          </Select>
        </div>
        {err && <div style={{ fontSize: 12, color: "var(--crit)" }}>{err}</div>}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 4 }}>
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={createAssetMutation.isPending || !hostname || !ip} onClick={submit}>
            {createAssetMutation.isPending ? "Creating..." : "Create"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export default function AssetList() {
  const navigate = useNavigate();
  const [zone, setZone] = useState("");
  const [search, setSearch] = useState("");
  const [crit, setCrit] = useState("");
  const [includePlaceholders, setIncludePlaceholders] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const assetsQuery = useAssetsQuery({ zone, search, criticality: crit || undefined });

  useEffect(() => {
    document.title = "Assets - ZeroTrustX";
  }, []);

  const data = assetsQuery.data || {};
  const allItems = Array.isArray(data.items) ? data.items : [];
  const items = includePlaceholders ? allItems : allItems.filter((item) => !item.is_placeholder);
  const total = includePlaceholders ? (data.total || items.length) : items.length;

  return (
    <>
      <PageHeader
        title="Assets"
        subtitle={`${total} total`}
        actions={
          <Button variant="primary" onClick={() => setShowAdd(true)}>
            <Plus size={14} /> Add Asset
          </Button>
        }
      />
      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
        <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: "14px 16px", display: "flex", gap: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div>
            <FieldLabel>Zone</FieldLabel>
            <div style={{ display: "flex", gap: 4 }}>
              {ZONES.map((z) => (
                <button key={z.label} onClick={() => setZone(z.value)} style={{
                  fontSize: 11, padding: "4px 10px", borderRadius: 6,
                  border: `1px solid ${zone === z.value ? "var(--ac-h)" : "var(--b0)"}`,
                  background: zone === z.value ? "var(--ac-d)" : "transparent",
                  color: zone === z.value ? "var(--ac-h)" : "var(--t2)",
                  cursor: "pointer", textTransform: "uppercase", letterSpacing: "0.06em",
                  transition: "background var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out)",
                }}>{z.label}</button>
              ))}
            </div>
          </div>
          <div style={{ width: 120 }}>
            <FieldLabel>Min Crit</FieldLabel>
            <Select value={crit} onChange={(e) => setCrit(e.target.value)}>
              <option value="">Any</option>
              {[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{`>= ${n}`}</option>)}
            </Select>
          </div>
          <div style={{ flex: 1, minWidth: 240 }}>
            <FieldLabel>Search</FieldLabel>
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="hostname or IP" />
          </div>
          <label style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 12, color: "var(--t2)" }}>
            <input type="checkbox" checked={includePlaceholders} onChange={(e) => setIncludePlaceholders(e.target.checked)} />
            Show placeholders
          </label>
        </section>

        <div style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", overflow: "hidden" }}>
          <Table
            columns={[
              { key: "hostname", label: "Hostname",
                render: (r) => (
                  <span>
                    <span className="mono" style={{ fontSize: 12, color: "var(--t1)" }}>{r.hostname}</span>
                    {r.is_placeholder && (
                      <span style={{ marginLeft: 6, fontSize: 10,
                        padding: "1px 6px", border: "1px solid var(--b0)",
                        borderRadius: 3, color: "var(--t3)" }}>auto</span>
                    )}
                  </span>
                ) },
              { key: "ip", label: "IP",
                render: (r) => <span className="mono" style={{ fontSize: 12, whiteSpace: "nowrap", color: "#94A3B8" }}>{r.ip || "-"}</span> },
              { key: "zone", label: "Zone",
                render: (r) => r.zone ? <ZoneBadge zone={r.zone} /> : <span style={{ color: "var(--t3)" }}>-</span> },
              { key: "owner", label: "Owner",
                render: (r) => r.owner || <span style={{ color: "var(--t3)" }}>-</span> },
              { key: "asset_criticality", label: "Criticality",
                render: (r) => <CritDots n={r.asset_criticality || 0} /> },
              { key: "open_incident_count", label: "Open Incidents",
                render: (r) => <span className="mono" style={{ fontSize: 12 }}>{r.open_incident_count ?? 0}</span> },
            ]}
            rows={items}
            onRowClick={(r) => navigate(`/assets/${r.id}`)}
            empty="No assets"
            rowKey={(r) => r.id}
            loading={assetsQuery.isLoading}
            error={assetsQuery.error?.message || null}
            pagination
            pageSize={10}
          />
        </div>
      </div>
      <AddAssetModal
        open={showAdd}
        onClose={() => setShowAdd(false)}
      />
    </>
  );
}

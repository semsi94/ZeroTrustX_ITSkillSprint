import { useEffect, useMemo, useState } from "react";
import {
  Check,
  CheckCircle,
  Copy,
  Eye,
  EyeSlash,
  PencilSimple,
  HardDrives,
  ShieldCheck,
  X,
  XCircle,
} from "@phosphor-icons/react";
import PageHeader from "../../components/layout/PageHeader";
import Input, { Textarea } from "../../components/ui/Input";
import Button, { IconButton } from "../../components/ui/Button";
import Skeleton, { SkeletonRows } from "../../components/ui/Skeleton";
import { api } from "../../api/client";
import { useIntegrations } from "../../context/IntegrationContext";
import {
  useDisconnectSplunk,
  useIntegrationSchema,
  useSyncSplunkCache,
  useSystemInfo,
  useUpdateSettings,
} from "../../hooks/queries/useSettingsQueries";
import {
  useReputationProviderStatus,
  useSaveReputationSettings,
  useSyncRecentIps,
  useTestAbuseIpdb,
  useTestVirusTotal,
} from "../../hooks/queries/useReputationQueries";

const MASK = "********";
const FULL_MASK = "************";

const SPLUNK_FIELDS = [
  { key: "SPLUNK_HOST", label: "SPLUNK_HOST", description: "Splunk hostname or IP address" },
  { key: "SPLUNK_PORT", label: "SPLUNK_PORT", description: "Management port (default 8089)" },
  { key: "SPLUNK_USERNAME", label: "SPLUNK_USERNAME", description: "Splunk admin username" },
  { key: "SPLUNK_PASSWORD", label: "SPLUNK_PASSWORD", description: "Splunk admin password", secret: true },
  { key: "SPLUNK_HEC_TOKEN", label: "SPLUNK_HEC_TOKEN", description: "HTTP Event Collector token for write-back", secret: true },
  { key: "SPLUNK_HEC_URL", label: "SPLUNK_HEC_URL", description: "HEC endpoint URL (e.g. https://splunk:8088/services/collector)" },
];

const PFSENSE_FIELDS = [
  { key: "PFSENSE_HOST", label: "PFSENSE_HOST", description: "pfSense hostname or IP address" },
  { key: "PFSENSE_USERNAME", label: "PFSENSE_USERNAME", description: "pfSense admin username" },
  { key: "PFSENSE_PASSWORD", label: "PFSENSE_PASSWORD", description: "pfSense admin password", secret: true },
  { key: "PFSENSE_VERIFY_SSL", label: "PFSENSE_VERIFY_SSL", description: "Boolean only: true or false" },
  { key: "PFSENSE_CA_CERT_TEXT", label: "PFSENSE_CA_CERT_TEXT", description: "CA certificate PEM text", secret: true },
  { key: "PFSENSE_CA_CERT_PATH", label: "PFSENSE_CA_CERT_PATH", description: "Optional backend-local CA certificate path" },
  { key: "PFSENSE_BLOCK_ALIAS", label: "PFSENSE_BLOCK_ALIAS", description: "Name of the block alias in pfSense (e.g. SOC_BLOCK_TEMP)" },
  { key: "PFSENSE_TIMEOUT", label: "PFSENSE_TIMEOUT", description: "Connection timeout in seconds" },
];

const REPUTATION_FIELDS = [
  { key: "ABUSEIPDB_API_KEY", label: "ABUSEIPDB_API_KEY", description: "AbuseIPDB API key for IP abuse confidence checks", secret: true },
  { key: "VIRUSTOTAL_API_KEY", label: "VIRUSTOTAL_API_KEY", description: "VirusTotal API v3 key for IP address reports", secret: true },
  { key: "IP_REPUTATION_ENABLED", label: "IP_REPUTATION_ENABLED", description: "Enable IP reputation enrichment" },
  { key: "IP_REPUTATION_AUTO_INCIDENT_ENABLED", label: "IP_REPUTATION_AUTO_INCIDENT_ENABLED", description: "Create pending candidates for malicious public IPs" },
];

const panelSurface = {
  background: "var(--s2)",
  border: "1px solid var(--b1)",
  borderRadius: "var(--r-lg)",
  boxShadow: "var(--el-1)",
};

const insetSurface = {
  background: "var(--s1)",
  border: "1px solid var(--b0)",
  borderRadius: "var(--r-md)",
};

const fieldLabelStyle = {
  display: "flex",
  flexDirection: "column",
  gap: 6,
  color: "var(--t3)",
  fontSize: 11,
  fontWeight: 700,
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  minWidth: 0,
};

function relativeTime(iso) {
  if (!iso) return "Never tested";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "Never tested";
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function maskValue(value, info, secret) {
  const isSet = info?.is_set || !!value;
  if (!isSet) {
    return <span style={{ color: "var(--t3)", fontStyle: "italic" }}>Not set</span>;
  }
  if (secret) return <span className="mono">{FULL_MASK}</span>;
  const safe = String(value || "");
  if (!safe) return <span className="mono">{MASK}</span>;
  return <span className="mono">{safe.slice(0, 4)}{MASK}</span>;
}

function splunkSearchReady(status) {
  return !!(status?.search_connected || status?.connected);
}

function StatusBadgeLarge({ status, integrationKey }) {
  const configured = !!status?.configured;
  const connected = integrationKey === "splunk" ? splunkSearchReady(status) : !!status?.connected;
  const fullyConnected = integrationKey === "splunk"
    ? !!(connected && status?.hec_configured && status?.hec_connected)
    : connected;
  let bg = "rgba(220,38,38,0.12)";
  let border = "rgba(220,38,38,0.40)";
  let color = "#FCA5A5";
  let text = "Not Configured";
  if (configured && fullyConnected) {
    bg = "rgba(22,163,74,0.16)";
    border = "rgba(22,163,74,0.55)";
    color = "#86EFAC";
    text = "Connected";
  } else if (configured && connected && integrationKey === "splunk") {
    bg = "rgba(37,99,235,0.14)";
    border = "rgba(37,99,235,0.50)";
    color = "#93C5FD";
    text = "Search Ready";
  } else if (configured) {
    bg = "rgba(202,138,4,0.16)";
    border = "rgba(202,138,4,0.55)";
    color = "#FDE68A";
    text = "! Error";
  }
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "5px 11px",
        borderRadius: 999,
        background: bg,
        border: `1px solid ${border}`,
        color,
        fontSize: 12,
        fontWeight: 700,
        minWidth: 122,
      }}
    >
      {text}
    </div>
  );
}

function TestPanel({ integrationKey, status, testState, onTest }) {
  const current = testState?.status || status || {};
  const testedAt = testState?.testedAt || current.tested_at;
  const connected = integrationKey === "splunk" ? splunkSearchReady(current) : !!current.connected;
  const error = testState?.error ?? current.error;
  const hasRun = !!testedAt || !!testState;

  return (
    <div style={{ ...insetSurface, padding: "14px 16px", display: "flex", gap: 16, alignItems: "center" }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        {!hasRun && (
          <div style={{ color: "var(--t3)", fontSize: 13 }}>
            No connection test has been run yet.
          </div>
        )}
        {hasRun && connected && (
          <div style={{ display: "flex", alignItems: "flex-start", gap: 9 }}>
            <CheckCircle size={16} color="var(--low)" />
            <div>
              <div style={{ color: "#86EFAC", fontSize: 13, fontWeight: 600 }}>
                {integrationKey === "splunk" ? "Management API connected" : "Connected successfully"}
              </div>
              {integrationKey === "splunk" && (
                <div style={{ color: "var(--t3)", fontSize: 12, marginTop: 2 }}>
                  HEC: {current.hec_configured
                    ? (current.hec_connected ? "connected" : `error - ${current.hec_error || current.error || "unreachable"}`)
                    : "not configured"}
                  {" | "}Saved searches: {current.saved_searches_accessible ? "accessible" : "not verified"}
                  {" | "}Alerts: {current.alerts_accessible ? "accessible" : "not verified"}
                </div>
              )}
              <div className="mono" style={{ color: "var(--t3)", fontSize: 11, marginTop: 2 }}>
                {testedAt || ""}
              </div>
            </div>
          </div>
        )}
        {hasRun && !connected && (
          <div style={{ display: "flex", alignItems: "flex-start", gap: 9 }}>
            <XCircle size={16} color="var(--crit)" style={{ marginTop: 2, flexShrink: 0 }} />
            <div>
              <div style={{ color: "#FCA5A5", fontSize: 13, fontWeight: 600, whiteSpace: "pre-wrap" }}>
                {error || "Connection failed"}
              </div>
              <div className="mono" style={{ color: "var(--t3)", fontSize: 11, marginTop: 2 }}>
                {testedAt || ""}
              </div>
            </div>
          </div>
        )}
      </div>
      <Button variant="secondary" onClick={onTest} disabled={testState?.loading}>
        {testState?.loading && (
          <span
            style={{
              width: 12,
              height: 12,
              borderRadius: 6,
              border: "2px solid rgba(255,255,255,0.22)",
              borderTopColor: "var(--ac-h)",
              animation: "spin 800ms linear infinite",
            }}
          />
        )}
        {testState?.loading ? "Testing" : "Test Connection"}
      </Button>
    </div>
  );
}

function SplunkCacheControls({ onChanged }) {
  const syncMutation = useSyncSplunkCache();
  const disconnectMutation = useDisconnectSplunk();
  const [message, setMessage] = useState(null);

  async function syncCache() {
    setMessage(null);
    try {
      const data = await syncMutation.mutateAsync({ timeRange: "Last 24h", limit: 1000 });
      setMessage(data.error || `Cached ${data.cached || 0} recent Splunk events`);
      onChanged?.();
    } catch (e) {
      setMessage(e?.message || "Cache sync failed");
    }
  }

  async function disconnect() {
    if (!window.confirm("Disconnect Splunk and clear cached Splunk logs?")) return;
    setMessage(null);
    try {
      const data = await disconnectMutation.mutateAsync();
      setMessage(`Splunk disconnected. Deleted ${data.deletedCachedEvents || 0} cached events.`);
      onChanged?.();
    } catch (e) {
      setMessage(e?.message || "Disconnect failed");
    }
  }

  const busy = syncMutation.isPending || disconnectMutation.isPending;

  return (
    <div style={{ ...insetSurface, padding: "12px 14px", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
      <Button variant="secondary" disabled={busy} onClick={syncCache}>
        {syncMutation.isPending ? "Syncing" : "Sync recent Splunk logs"}
      </Button>
      <Button variant="danger" disabled={busy} onClick={disconnect}>
        {disconnectMutation.isPending ? "Disconnecting" : "Disconnect Splunk"}
      </Button>
      {message && <span style={{ color: "var(--t3)", fontSize: 12 }}>{message}</span>}
    </div>
  );
}

function EnvFieldRow({ integration, field, info, isLast, onSaveField }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [show, setShow] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    setDraft(field.secret ? "" : (info?.value || ""));
    setEditing(false);
    setError(null);
  }, [field.key, field.secret, info?.value, info?.is_set]);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      await onSaveField(integration, field.key, draft);
      setEditing(false);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setError(e?.message || "Failed to save integration");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "10px 0",
        borderBottom: isLast ? "none" : "1px solid var(--b0)",
      }}
    >
      <div style={{ minWidth: 140, width: 180 }}>
        <div style={{ fontSize: 13, color: "var(--t2)", fontWeight: 600 }}>{field.label}</div>
        <div style={{ fontSize: 11, color: "var(--t3)", lineHeight: 1.35, marginTop: 2 }}>
          {field.description}
        </div>
      </div>

      <div style={{ flex: 1, minWidth: 0 }}>
        {!editing ? (
          <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--t2)", fontSize: 13 }}>
            {maskValue(info?.value, info, field.secret)}
            {saved && <Check size={14} color="var(--low)" />}
          </div>
        ) : (
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <div style={{ position: "relative", flex: 1 }}>
              <Input
                type={field.secret && !show ? "password" : "text"}
                value={draft}
                autoFocus
                onChange={(e) => setDraft(e.target.value)}
                style={{ paddingRight: field.secret ? 36 : undefined }}
              />
              {field.secret && (
                <button
                  type="button"
                  onClick={() => setShow((v) => !v)}
                  style={{
                    position: "absolute",
                    right: 8,
                    top: "50%",
                    transform: "translateY(-50%)",
                    background: "transparent",
                    border: "none",
                    color: "var(--t3)",
                    cursor: "pointer",
                    padding: 2,
                  }}
                >
                  {show ? <EyeSlash size={15} /> : <Eye size={15} />}
                </button>
              )}
            </div>
            <Button variant="primary" disabled={saving} onClick={save} style={{ padding: "6px 11px" }}>
              Save
            </Button>
            <Button
              variant="ghost"
              disabled={saving}
              onClick={() => {
                setEditing(false);
                setError(null);
              }}
              style={{ padding: "6px 11px" }}
            >
              Cancel
            </Button>
          </div>
        )}
        {error && <div style={{ color: "var(--crit)", fontSize: 11, marginTop: 5 }}>{error}</div>}
      </div>

      <div style={{ width: 36, display: "flex", justifyContent: "flex-end" }}>
        {!editing && (
          <IconButton
            title={`Edit ${field.label}`}
            onClick={() => {
              setDraft(field.secret ? "" : (info?.value || ""));
              setEditing(true);
            }}
          >
            <PencilSimple size={16} />
          </IconButton>
        )}
      </div>
    </div>
  );
}

function IntegrationCard({ integrationKey, name, description, icon: Icon, fields, schema, status, onSaved, onSaveField }) {
  const { forceRefresh } = useIntegrations();
  const [testState, setTestState] = useState(null);

  async function runTest() {
    setTestState({ loading: true, error: null, status: null, testedAt: null });
    try {
      const data = await forceRefresh();
      const next = data?.[integrationKey];
      const ok = integrationKey === "splunk" ? splunkSearchReady(next) : !!next?.connected;
      setTestState({
        loading: false,
        error: ok ? null : (next?.error || "Connection failed"),
        status: next,
        testedAt: next?.tested_at || new Date().toISOString(),
      });
    } catch (e) {
      setTestState({
        loading: false,
        error: e?.message || "Connection test failed",
        status: { connected: false },
        testedAt: new Date().toISOString(),
      });
    }
  }

  return (
    <section style={{ ...panelSurface, padding: 18 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 18, alignItems: "flex-start" }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
          <div style={{ color: "var(--ac-h)", marginTop: 2 }}>
            <Icon size={16} />
          </div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: "var(--t1)" }}>{name}</div>
            <div style={{ fontSize: 13, color: "var(--t3)", marginTop: 2 }}>{description}</div>
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <StatusBadgeLarge integrationKey={integrationKey} status={testState?.status || status} />
          <div style={{ fontSize: 11, color: "var(--t3)", marginTop: 6 }}>
            Last tested: {relativeTime((testState?.status || status)?.tested_at)}
          </div>
        </div>
      </div>

      <div style={{ height: 1, background: "var(--b0)", margin: "16px 0 4px" }} />

      <div>
        {fields.map((field, index) => (
          <EnvFieldRow
            key={field.key}
            integration={integrationKey}
            field={field}
            info={schema?.fields?.[field.key]}
            isLast={index === fields.length - 1}
            onSaveField={onSaveField}
          />
        ))}
      </div>

      <div style={{ height: 1, background: "var(--b0)", margin: "4px 0 16px" }} />

      <TestPanel integrationKey={integrationKey} status={status} testState={testState} onTest={runTest} />
      {integrationKey === "splunk" && (
        <div style={{ marginTop: 12 }}>
          <SplunkCacheControls onChanged={onSaved} />
        </div>
      )}
    </section>
  );
}

function boolFromValue(value) {
  if (value === true) return true;
  return String(value || "").trim().toLowerCase() === "true";
}

function fieldValue(schema, key, fallback = "") {
  return schema?.fields?.[key]?.value ?? fallback;
}

function PfSenseCard({ schema, status, onSaved, onSaveValues, saving }) {
  const { forceRefresh } = useIntegrations();
  const [draft, setDraft] = useState({
    host: "",
    username: "",
    password: "",
    verifySsl: false,
    caCertText: "",
    caCertPath: "",
    blockAlias: "SOC_BLOCK_TEMP",
    timeout: "10",
  });
  const [message, setMessage] = useState(null);
  const [formError, setFormError] = useState(null);
  const [testState, setTestState] = useState(null);

  useEffect(() => {
    setDraft({
      host: fieldValue(schema, "PFSENSE_HOST"),
      username: fieldValue(schema, "PFSENSE_USERNAME"),
      password: "",
      verifySsl: boolFromValue(fieldValue(schema, "PFSENSE_VERIFY_SSL", "false")),
      caCertText: "",
      caCertPath: fieldValue(schema, "PFSENSE_CA_CERT_PATH"),
      blockAlias: fieldValue(schema, "PFSENSE_BLOCK_ALIAS", "SOC_BLOCK_TEMP"),
      timeout: fieldValue(schema, "PFSENSE_TIMEOUT", "10"),
    });
    setFormError(null);
    setMessage(null);
  }, [schema]);

  const passwordConfigured = !!schema?.fields?.PFSENSE_PASSWORD?.is_set;
  const certTextConfigured = !!schema?.fields?.PFSENSE_CA_CERT_TEXT?.is_set;
  const certPathConfigured = !!schema?.fields?.PFSENSE_CA_CERT_PATH?.is_set;
  const certConfigured = certTextConfigured || certPathConfigured || status?.ca_cert_configured;

  function update(key, value) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function buildPayload({ clearCert = false } = {}) {
    const certText = draft.caCertText.trim();
    const certPath = draft.caCertPath.trim();
    if (certText && (!certText.includes("BEGIN CERTIFICATE") || !certText.includes("END CERTIFICATE"))) {
      throw new Error("Invalid CA certificate format.");
    }
    if (draft.verifySsl && !certText && !certPath && !certConfigured && !clearCert) {
      throw new Error("Verify SSL requires CA certificate text or CA certificate path.");
    }

    const payload = {
      PFSENSE_HOST: draft.host.trim(),
      PFSENSE_USERNAME: draft.username.trim(),
      PFSENSE_VERIFY_SSL: draft.verifySsl ? "true" : "false",
      PFSENSE_CA_CERT_PATH: certPath,
      PFSENSE_BLOCK_ALIAS: draft.blockAlias.trim(),
      PFSENSE_TIMEOUT: String(draft.timeout || "10").trim(),
    };
    if (draft.password.trim()) payload.PFSENSE_PASSWORD = draft.password;
    if (certText) payload.PFSENSE_CA_CERT_TEXT = certText;
    if (clearCert) payload.PFSENSE_CA_CERT_TEXT = "";
    return payload;
  }

  async function save(clearCert = false) {
    setFormError(null);
    setMessage(null);
    try {
      const payload = buildPayload({ clearCert });
      await onSaveValues(payload);
      setDraft((current) => ({ ...current, password: "", caCertText: clearCert ? "" : current.caCertText }));
      setMessage(clearCert ? "CA certificate cleared." : "pfSense settings saved.");
      onSaved?.();
    } catch (e) {
      setFormError(e?.message || "Failed to save pfSense settings");
    }
  }

  async function runTest() {
    setTestState({ loading: true, error: null, status: null, testedAt: null });
    try {
      const data = await forceRefresh();
      const next = data?.pfsense;
      setTestState({
        loading: false,
        error: next?.connected ? null : (next?.error || "Connection failed"),
        status: next,
        testedAt: next?.tested_at || new Date().toISOString(),
      });
    } catch (e) {
      setTestState({
        loading: false,
        error: e?.message || "Connection test failed",
        status: { connected: false },
        testedAt: new Date().toISOString(),
      });
    }
  }

  return (
    <section style={{ ...panelSurface, padding: 18 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 18, alignItems: "flex-start" }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
          <div style={{ color: "var(--ac-h)", marginTop: 2 }}><ShieldCheck size={16} /></div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: "var(--t1)" }}>pfSense</div>
            <div style={{ fontSize: 13, color: "var(--t3)", marginTop: 2 }}>Firewall alias updates for containment response</div>
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <StatusBadgeLarge integrationKey="pfsense" status={testState?.status || status} />
          <div style={{ fontSize: 11, color: "var(--t3)", marginTop: 6 }}>
            Last tested: {relativeTime((testState?.status || status)?.tested_at)}
          </div>
        </div>
      </div>

      <div style={{ height: 1, background: "var(--b0)", margin: "16px 0" }} />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 12 }}>
        <label style={fieldLabelStyle}>Host<Input value={draft.host} onChange={(e) => update("host", e.target.value)} placeholder="https://pfsense.local" /></label>
        <label style={fieldLabelStyle}>Username<Input value={draft.username} onChange={(e) => update("username", e.target.value)} /></label>
        <label style={fieldLabelStyle}>Password<Input type="password" value={draft.password} onChange={(e) => update("password", e.target.value)} placeholder={passwordConfigured ? FULL_MASK : ""} /></label>
        <label style={fieldLabelStyle}>Block Alias<Input value={draft.blockAlias} onChange={(e) => update("blockAlias", e.target.value)} placeholder="SOC_BLOCK_TEMP" /></label>
        <label style={fieldLabelStyle}>Timeout<Input value={draft.timeout} onChange={(e) => update("timeout", e.target.value)} placeholder="10" /></label>
        <div style={{ ...fieldLabelStyle, justifyContent: "end" }}>
          <button
            type="button"
            onClick={() => update("verifySsl", !draft.verifySsl)}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              width: "100%",
              background: draft.verifySsl ? "var(--ac-d)" : "var(--s1)",
              border: `1px solid ${draft.verifySsl ? "var(--ac-r)" : "var(--b1)"}`,
              color: draft.verifySsl ? "var(--ac-h)" : "var(--t2)",
              borderRadius: "var(--r-md)",
              padding: "8px 11px",
            }}
          >
            <span>Verify SSL</span>
            <span className="mono">{draft.verifySsl ? "true" : "false"}</span>
          </button>
        </div>
      </div>

      <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
        <label style={fieldLabelStyle}>
          CA Certificate Path
          <Input value={draft.caCertPath} onChange={(e) => update("caCertPath", e.target.value)} placeholder="/etc/ssl/certs/pfsense-ca.crt" />
        </label>
        <label style={fieldLabelStyle}>
          CA Certificate Text
          <Textarea
            mono
            value={draft.caCertText}
            onChange={(e) => update("caCertText", e.target.value)}
            placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
            style={{ minHeight: 118 }}
          />
        </label>
        <div style={{ color: "var(--t3)", fontSize: 12 }}>
          Paste the CA certificate, including BEGIN CERTIFICATE and END CERTIFICATE. Current CA certificate status: {certConfigured ? "configured" : "not configured"}.
        </div>
      </div>

      {formError && <div style={{ color: "var(--crit)", fontSize: 13, marginTop: 12 }}>{formError}</div>}
      {message && <div style={{ color: "var(--low)", fontSize: 13, marginTop: 12 }}>{message}</div>}

      <div style={{ display: "flex", gap: 8, marginTop: 14, flexWrap: "wrap" }}>
        <Button variant="primary" onClick={() => save(false)} disabled={saving}>
          {saving ? "Saving" : "Save pfSense Settings"}
        </Button>
        {certConfigured && (
          <Button variant="danger" onClick={() => save(true)} disabled={saving}>
            Clear CA Certificate
          </Button>
        )}
      </div>

      <div style={{ marginTop: 14 }}>
        <TestPanel integrationKey="pfsense" status={status} testState={testState} onTest={runTest} />
      </div>
    </section>
  );
}

function ReputationCard({ schema, status, onSaved }) {
  const providerQuery = useReputationProviderStatus();
  const saveMutation = useSaveReputationSettings();
  const testAbuse = useTestAbuseIpdb();
  const testVt = useTestVirusTotal();
  const syncRecent = useSyncRecentIps();

  async function saveField(_integration, fieldKey, value) {
    const payload = {};
    if (fieldKey === "ABUSEIPDB_API_KEY") payload.abuseipdb_api_key = value;
    if (fieldKey === "VIRUSTOTAL_API_KEY") payload.virustotal_api_key = value;
    if (fieldKey === "IP_REPUTATION_ENABLED") payload.enabled = String(value).toLowerCase() === "true";
    if (fieldKey === "IP_REPUTATION_AUTO_INCIDENT_ENABLED") payload.auto_incident_enabled = String(value).toLowerCase() === "true";
    await saveMutation.mutateAsync(payload);
    onSaved?.();
  }

  const provider = providerQuery.data || {};
  const full = provider.full_reputation_available || status?.full_reputation_available;

  return (
    <section style={{ ...panelSurface, padding: 18 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 18, alignItems: "flex-start" }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
          <div style={{ color: "var(--ac-h)", marginTop: 2 }}><ShieldCheck size={16} /></div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: "var(--t1)" }}>Reputation Intelligence</div>
            <div style={{ fontSize: 13, color: "var(--t3)", marginTop: 2 }}>AbuseIPDB and VirusTotal enrichment for public IP observables</div>
          </div>
        </div>
        <StatusBadgeLarge integrationKey="reputation" status={{ configured: full, connected: full }} />
      </div>
      {!full && (
        <div style={{ marginTop: 14, color: "var(--med)", fontSize: 13 }}>
          Full IP reputation requires both AbuseIPDB and VirusTotal.
        </div>
      )}
      <div style={{ height: 1, background: "var(--b0)", margin: "16px 0 4px" }} />
      {REPUTATION_FIELDS.map((field, index) => (
        <EnvFieldRow
          key={field.key}
          integration="reputation"
          field={field}
          info={schema?.fields?.[field.key]}
          isLast={index === REPUTATION_FIELDS.length - 1}
          onSaveField={saveField}
        />
      ))}
      <div style={{ height: 1, background: "var(--b0)", margin: "4px 0 16px" }} />
      <div style={{ ...insetSurface, padding: "12px 14px", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <Button variant="secondary" onClick={() => testAbuse.mutate()} disabled={testAbuse.isPending}>Test AbuseIPDB</Button>
        <Button variant="secondary" onClick={() => testVt.mutate()} disabled={testVt.isPending}>Test VirusTotal</Button>
        <Button variant="secondary" onClick={() => syncRecent.mutate()} disabled={syncRecent.isPending}>Sync Recent IPs</Button>
        <span style={{ color: "var(--t3)", fontSize: 12 }}>
          AbuseIPDB: {provider.abuseipdb?.configured ? (provider.abuseipdb?.connected ? "connected" : "configured") : "not configured"}
          {" | "}VirusTotal: {provider.virustotal?.configured ? (provider.virustotal?.connected ? "connected" : "configured") : "not configured"}
        </span>
      </div>
      {(testAbuse.data || testVt.data || syncRecent.data) && (
        <div style={{ color: "var(--t3)", fontSize: 12, marginTop: 10 }}>
          {testAbuse.data ? `AbuseIPDB: ${testAbuse.data.success ? "connected" : testAbuse.data.error}` : ""}
          {testVt.data ? ` VirusTotal: ${testVt.data.success ? "connected" : testVt.data.error}` : ""}
          {syncRecent.data ? ` Queued ${syncRecent.data.queued || 0}, cached ${syncRecent.data.cached || 0}.` : ""}
        </div>
      )}
    </section>
  );
}

function SystemStatus() {
  const systemInfoQuery = useSystemInfo();
  const [copied, setCopied] = useState(false);
  const info = systemInfoQuery.data || null;

  const webhookUrl = useMemo(() => {
    const path = info?.webhook_url || "/webhooks/splunk";
    try {
      return new URL(path, api.defaults.baseURL).toString();
    } catch {
      return `${window.location.protocol}//${window.location.hostname}:8000${path}`;
    }
  }, [info?.webhook_url]);

  async function copy() {
    await navigator.clipboard.writeText(webhookUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  if (systemInfoQuery.isLoading) {
    return (
      <section style={{ ...panelSurface, padding: 18 }}>
        <Skeleton width={140} height={16} />
        <div style={{ marginTop: 16 }}><SkeletonRows rows={4} /></div>
      </section>
    );
  }

  if (systemInfoQuery.error) {
    return (
      <section style={{ ...panelSurface, padding: 18 }}>
        <div style={{ color: "var(--crit)", fontSize: 13 }}>{systemInfoQuery.error.message}</div>
        <Button variant="secondary" onClick={() => systemInfoQuery.refetch()} style={{ marginTop: 12 }}>Retry</Button>
      </section>
    );
  }

  const stats = [
    ["App Version", info?.app_version || "-"],
    ["DB", info?.db_connected ? "Connected" : "Error"],
    ["Redis", info?.redis_connected ? "Connected" : "Error"],
    ["Celery", info?.celery_connected ? "Connected" : "Error"],
    ["MITRE", info?.mitre_synced ? "Synced" : "Missing"],
    ["Total Incidents", info?.total_incidents ?? 0],
    ["Total Alerts", info?.total_alerts ?? 0],
    ["Total Assets", info?.total_assets ?? 0],
  ];

  return (
    <section style={{ ...panelSurface, padding: 18 }}>
      <div style={{ fontSize: 16, fontWeight: 700, color: "var(--t1)" }}>System Status</div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginTop: 16 }}>
        {stats.map(([label, value]) => {
          const isStatus = label === "DB" || label === "Redis" || label === "Celery" || label === "MITRE";
          const ok = value === "Connected" || value === "Synced";
          return (
            <div key={label} style={{ ...insetSurface, padding: 12 }}>
              <div style={{ fontSize: 11, color: "var(--t3)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                {label}
              </div>
              <div
                className={typeof value === "number" ? "mono" : ""}
                style={{
                  color: isStatus ? (ok ? "var(--low)" : "var(--crit)") : "var(--t1)",
                  fontSize: 14,
                  marginTop: 5,
                  fontWeight: 600,
                }}
              >
                {value}
              </div>
            </div>
          );
        })}
      </div>

      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: 12, color: "var(--t2)", marginBottom: 6 }}>
          Webhook Endpoint (configure this URL in Splunk alert actions)
        </div>
        <div style={{ ...insetSurface, padding: "9px 10px", display: "flex", alignItems: "center", gap: 8 }}>
          <div className="mono" style={{ flex: 1, minWidth: 0, color: "var(--t1)", fontSize: 12, overflow: "hidden", textOverflow: "ellipsis" }}>
            {webhookUrl}
          </div>
          <Button variant="secondary" onClick={copy} style={{ padding: "6px 11px" }}>
            {copied ? <Check size={14} /> : <Copy size={14} />}
            {copied ? "Copied!" : "Copy"}
          </Button>
        </div>
      </div>
    </section>
  );
}

export default function Integrations() {
  const { status, forceRefresh } = useIntegrations();
  const schemaQuery = useIntegrationSchema();
  const updateSettingsMutation = useUpdateSettings();

  useEffect(() => {
    document.title = "Integrations - ZeroTrustX";
  }, []);

  async function afterFieldSave() {
    await schemaQuery.refetch();
    await forceRefresh();
  }

  async function saveField(integration, fieldKey, value) {
    await updateSettingsMutation.mutateAsync({
      integration,
      values: { [fieldKey]: value },
    });
    await afterFieldSave();
  }

  async function saveIntegration(integration, values) {
    await updateSettingsMutation.mutateAsync({ integration, values });
    await afterFieldSave();
  }

  const loading = schemaQuery.isLoading;
  const error = schemaQuery.error?.message || null;
  const schema = schemaQuery.data || null;

  return (
    <>
      <PageHeader title="Integrations" subtitle="Configure data sources and firewall response" />
      <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
        {loading && (
          <>
            <section style={{ ...panelSurface, padding: 18 }}><SkeletonRows rows={6} /></section>
            <section style={{ ...panelSurface, padding: 18 }}><SkeletonRows rows={5} /></section>
          </>
        )}

        {!loading && error && (
          <section style={{ ...panelSurface, padding: 18 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--crit)" }}>
              <X size={16} /> {error}
            </div>
            <Button variant="secondary" onClick={() => schemaQuery.refetch()} style={{ marginTop: 12 }}>Retry</Button>
          </section>
        )}

        {!loading && !error && (
          <>
            <IntegrationCard
              integrationKey="splunk"
              name="Splunk"
              description="Search API for investigations and HEC for write-back"
              icon={HardDrives}
              fields={SPLUNK_FIELDS}
              schema={schema?.splunk}
              status={status?.splunk}
              onSaved={afterFieldSave}
              onSaveField={saveField}
            />
            <PfSenseCard
              schema={schema?.pfsense}
              status={status?.pfsense}
              onSaved={afterFieldSave}
              onSaveValues={(values) => saveIntegration("pfsense", values)}
              saving={updateSettingsMutation.isPending}
            />
            <ReputationCard
              schema={schema?.reputation}
              status={status?.reputation}
              onSaved={afterFieldSave}
            />
            <SystemStatus />
          </>
        )}
      </div>
    </>
  );
}

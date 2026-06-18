import { useEffect, useMemo, useState } from "react";
import { DownloadSimple, MagnifyingGlass, Trash, X } from "@phosphor-icons/react";
import Modal from "../ui/Modal";
import Button from "../ui/Button";
import Input from "../ui/Input";
import EmptyState from "../ui/EmptyState";
import {
  useAnalyzeIncidentMitre,
  useCreateIncidentMitreLink,
  useDeleteIncidentMitreLink,
  useExportNavigatorLayer,
  useIncidentMitre,
  useMitreHealth,
  useMitreMatrix,
  useSyncMitreData,
} from "../../hooks/queries/useMitreQueries";

const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

function mappingKey(mapping) {
  return `${mapping.tactic_id || "unknown"}:${mapping.subtechnique_id || mapping.technique_id}`;
}

function techniqueKey(technique) {
  return technique.subtechnique_id || technique.technique_id;
}

function tacticTechniqueKey(tacticId, technique) {
  return `${tacticId || technique.current_tactic_id || "unknown"}:${techniqueKey(technique)}`;
}

function confidenceTone(mapping) {
  if (mapping.mapping_source === "analyst") return "#56CCF2";
  const score = Number(mapping.confidence_score || 0);
  if (score >= 80) return "var(--sev-low)";
  if (score >= 50) return "var(--sev-med)";
  return "var(--sev-high)";
}

export function IncidentMitreSummaryCard({ incidentId, canWrite, onOpen }) {
  const mitreQuery = useIncidentMitre(incidentId);
  const mappings = mitreQuery.data?.mappings || [];
  const summary = mitreQuery.data?.summary || {};
  const topTactics = (summary.top_tactics || []).slice(0, 2).map((t) => t.name).join(", ") || "No tactics mapped";
  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
        <div>
          <div style={{ color: "var(--t1)", fontWeight: 800 }}>MITRE ATT&CK Mapping</div>
          <div style={{ color: "var(--t3)", fontSize: 12, marginTop: 3 }}>
            {mappings.length} mapped technique{mappings.length === 1 ? "" : "s"} - highest confidence {summary.highest_confidence || 0}% - {topTactics}
          </div>
        </div>
        <Button variant="secondary" onClick={onOpen}>
          Open mapping
        </Button>
      </div>
      {!mappings.length && (
        <div style={{ color: "var(--t3)", fontSize: 12 }}>
          No ATT&CK mapping yet. {canWrite ? "Run analysis after evidence is attached." : "Mappings will appear when an analyst runs analysis."}
        </div>
      )}
    </div>
  );
}

export default function IncidentMitreWorkspace({ open, onClose, incidentId, canWrite, canAdmin }) {
  const [selected, setSelected] = useState(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [mappedOnly, setMappedOnly] = useState(false);
  const [showSubtechniques, setShowSubtechniques] = useState(true);
  const mitreQuery = useIncidentMitre(incidentId, { enabled: open && Boolean(incidentId) });
  const healthQuery = useMitreHealth({ enabled: open });
  const matrixQuery = useMitreMatrix({ enabled: open });
  const analyzeMutation = useAnalyzeIncidentMitre();
  const createMutation = useCreateIncidentMitreLink();
  const deleteMutation = useDeleteIncidentMitreLink();
  const exportMutation = useExportNavigatorLayer();
  const syncMutation = useSyncMitreData();
  const mappings = mitreQuery.data?.mappings || [];
  const health = healthQuery.data || {};
  const healthIssues = Array.isArray(health.issues) ? health.issues : [];
  const matrixDiffersFromOfficial = health?.matrix_matches_official === false;
  const selectedKey = selected?.technique ? `${selected.tactic?.tactic_id}:${techniqueKey(selected.technique)}` : null;

  useEffect(() => {
    if (!open) setDetailOpen(false);
  }, [open]);

  const mappedById = useMemo(() => {
    const map = new Map();
    mappings.forEach((mapping) => map.set(mappingKey(mapping), mapping));
    return map;
  }, [mappings]);

  const mappingsByTechnique = useMemo(() => {
    const map = new Map();
    mappings.forEach((mapping) => {
      const key = mapping.subtechnique_id || mapping.technique_id;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(mapping);
    });
    return map;
  }, [mappings]);

  const matrix = useMemo(() => {
    const query = filter.trim().toLowerCase();
    return (matrixQuery.data?.matrix || [])
      .slice()
      .sort((a, b) => {
        const orderA = Number(a.matrix_order || 0);
        const orderB = Number(b.matrix_order || 0);
        if (orderA && orderB) return orderA - orderB;
        return TACTIC_ORDER.indexOf(a.name) - TACTIC_ORDER.indexOf(b.name);
      })
      .map((tactic) => ({
        ...tactic,
        techniques: (tactic.techniques || []).filter((technique) => {
          if (!showSubtechniques && technique.is_subtechnique) return false;
          const key = tacticTechniqueKey(tactic.tactic_id, technique);
          const mapped = mappedById.has(key);
          if (mappedOnly && !mapped) return false;
          if (!query) return true;
          return `${technique.technique_id} ${technique.subtechnique_id || ""} ${technique.name}`.toLowerCase().includes(query);
        }),
      }))
      .filter((tactic) => (tactic.techniques || []).length > 0);
  }, [matrixQuery.data, mappedById, filter, mappedOnly, showSubtechniques]);
  const mappedCount = mappings.length;
  const visibleTechniqueCount = matrix.reduce((sum, tactic) => sum + (tactic.techniques || []).length, 0);

  const emptyMatrixTitle = mappedOnly
    ? "No mapped techniques for this incident yet"
    : filter.trim()
      ? "No techniques match this filter"
      : "MITRE matrix has no visible techniques";

  async function exportLayer() {
    const blob = await exportMutation.mutateAsync(incidentId);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-${incidentId}-attack-navigator-layer.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function addMapping({ tactic, technique }) {
    createMutation.mutate({
      incidentId,
      payload: {
        tactic_id: tactic.tactic_id,
        technique_id: technique.technique_id,
        subtechnique_id: technique.subtechnique_id || null,
        technique_name: technique.name,
        confidence_score: 100,
        mapping_source: "analyst",
        reason: "Analyst confirmed this ATT&CK technique from incident context.",
      },
    });
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="MITRE ATT&CK Mapping"
      width="min(1400px, calc(100vw - 48px))"
      height="min(900px, calc(100vh - 48px))"
      maxWidth="calc(100vw - 48px)"
      maxHeight="calc(100vh - 48px)"
      zIndex={5200}
      bodyStyle={{ padding: 16, display: "flex", flexDirection: "column", overflow: "hidden", minHeight: 0 }}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 14, minWidth: 0, minHeight: 0, height: "100%" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Search techniques" style={{ maxWidth: 280 }} />
          <Button variant={mappedOnly ? "primary" : "secondary"} onClick={() => setMappedOnly((v) => !v)}>Mapped only</Button>
          <Button variant={showSubtechniques ? "primary" : "secondary"} onClick={() => setShowSubtechniques((v) => !v)}>Sub-techniques</Button>
          {canWrite && <Button onClick={() => analyzeMutation.mutate(incidentId)} disabled={analyzeMutation.isPending}>Re-analyze MITRE</Button>}
          {canAdmin && (
            <Button variant="secondary" onClick={() => syncMutation.mutate()} disabled={syncMutation.isPending}>
              {syncMutation.isPending ? "Syncing..." : "Sync official data"}
            </Button>
          )}
          <Button variant="secondary" onClick={exportLayer} disabled={exportMutation.isPending}>
            <DownloadSimple size={15} /> Export Navigator Layer
          </Button>
        </div>

        {mitreQuery.error && <div style={{ color: "var(--crit)", fontSize: 13 }}>{mitreQuery.error.message}</div>}
        {matrixQuery.error && <div style={{ color: "var(--crit)", fontSize: 13 }}>MITRE data not synced: {matrixQuery.error.message}</div>}
        {healthQuery.error && (
          <div style={{ color: "var(--sev-med)", fontSize: 13 }}>
            MITRE health check failed. The matrix can still render, but sync status could not be verified.
          </div>
        )}
        {matrixDiffersFromOfficial && !healthIssues.length && (
          <div style={{ color: "var(--sev-med)", fontSize: 13 }}>
            Local MITRE matrix differs from official Enterprise ATT&CK. Re-sync recommended.
          </div>
        )}
        {!!healthIssues.length && (
          <div style={{ color: "var(--sev-med)", fontSize: 13 }}>
            MITRE matrix health warning: {healthIssues[0]} {canAdmin ? "Use Sync official data to repair the local ATT&CK cache." : "Ask an admin to sync official ATT&CK data."}
          </div>
        )}
        {syncMutation.data?.success === false && <div style={{ color: "var(--sev-med)", fontSize: 13 }}>{syncMutation.data.error}</div>}
        {syncMutation.data?.success === true && <div style={{ color: "var(--sev-low)", fontSize: 13 }}>Official MITRE ATT&CK data synced.</div>}
        {analyzeMutation.data?.summary && (
          <div style={{ color: "var(--t2)", fontSize: 13 }}>
            Analysis complete: {analyzeMutation.data.summary.mapped_count} mappings, highest confidence {analyzeMutation.data.summary.highest_confidence}%.
          </div>
        )}

        <div
          style={{
            display: "flex",
            gap: 14,
            minHeight: 0,
            flex: 1,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              flex: 1,
              minHeight: 0,
              minWidth: 0,
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                flex: 1,
                minHeight: 0,
                minWidth: 0,
                overflow: "hidden",
                border: "1px solid var(--b1)",
                borderRadius: 12,
                background: "var(--s2)",
                boxShadow: "var(--el-1)",
                display: "flex",
                flexDirection: "column",
              }}
            >
              <div
                style={{
                  flexShrink: 0,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                  padding: "11px 14px",
                  borderBottom: "1px solid var(--b1)",
                  background: "var(--s1)",
                  boxShadow: "none",
                }}
              >
                <div>
                  <div style={{ color: "var(--t1)", fontWeight: 850, fontSize: 13 }}>ATT&CK Enterprise Matrix</div>
                  <div style={{ color: "var(--t3)", fontSize: 11, marginTop: 2 }}>
                    {matrix.length} tactic column{matrix.length === 1 ? "" : "s"} - {visibleTechniqueCount} visible technique{visibleTechniqueCount === 1 ? "" : "s"}
                  </div>
                </div>
                <div className="mono" style={{ color: "var(--t2)", fontSize: 11, border: "1px solid var(--b1)", borderRadius: 999, padding: "4px 8px", whiteSpace: "nowrap", background: "var(--s2)" }}>
                  {mappedCount} mapped
                </div>
              </div>
              <div
                className="mitre-matrix-scroll"
                style={{
                  flex: 1,
                  height: "auto",
                  overflow: "auto",
                  minHeight: 0,
                  minWidth: 0,
                  padding: 12,
                  paddingBottom: 18,
                  scrollbarGutter: "stable both-edges",
                }}
              >
                {matrixQuery.isLoading ? (
                  <EmptyState icon={MagnifyingGlass} title="Loading ATT&CK matrix" subtitle="Fetching local MITRE tactics and techniques." />
                ) : !matrix.length ? (
                  <EmptyState
                    icon={MagnifyingGlass}
                    title={emptyMatrixTitle}
                    subtitle={mappedOnly ? "Run analysis or add an analyst mapping to highlight ATT&CK techniques." : "Adjust the filters or sync official ATT&CK data if the matrix is empty."}
                  />
                ) : (
                  <div style={{ display: "flex", alignItems: "stretch", gap: 12, width: "max-content", minWidth: "100%" }}>
                    {matrix.map((tactic) => (
                      <div
                        key={tactic.tactic_id}
                        data-tactic-id={tactic.tactic_id}
                        style={{
                          width: 250,
                          minWidth: 250,
                          maxWidth: 250,
                          flex: "0 0 250px",
                          display: "flex",
                          flexDirection: "column",
                          borderRight: "1px solid var(--b0)",
                          paddingRight: 10,
                          boxSizing: "border-box",
                        }}
                      >
                        <div
                          style={{
                            position: "sticky",
                            top: 0,
                            zIndex: 5,
                            margin: "0 0 10px",
                            padding: "10px",
                            background: "var(--s3)",
                            border: "1px solid var(--b2)",
                            borderBottom: "1px solid var(--b3)",
                            borderRadius: 9,
                            boxShadow: "var(--el-1)",
                            minHeight: 64,
                          }}
                        >
                          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8 }}>
                            <div>
                              <div style={{ color: "var(--t1)", fontWeight: 850, fontSize: 12, lineHeight: 1.25 }}>{tactic.name}</div>
                              <div className="mono" style={{ color: "var(--t3)", fontSize: 10, marginTop: 3 }}>{tactic.tactic_id}</div>
                            </div>
                            <div className="mono" style={{ color: "var(--t2)", border: "1px solid var(--b1)", borderRadius: 999, padding: "2px 6px", fontSize: 10, whiteSpace: "nowrap", background: "var(--s2)" }}>
                              {(tactic.techniques || []).length}
                            </div>
                          </div>
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8, overflow: "visible" }}>
                          {(tactic.techniques || []).map((technique) => {
                            const key = techniqueKey(technique);
                            const mapping = mappedById.get(tacticTechniqueKey(tactic.tactic_id, technique));
                            const mapped = Boolean(mapping);
                            const isSelected = selectedKey === `${tactic.tactic_id}:${key}`;
                            const appearsIn = Array.isArray(technique.appears_in_tactics) ? technique.appears_in_tactics : [];
                            const otherTacticCount = Math.max(appearsIn.length - 1, 0);
                            return (
                              <button
                                key={`${tactic.tactic_id}-${key}-${technique.name}`}
                                type="button"
                                onClick={() => {
                                  setSelected({ tactic, technique, mapping });
                                  setDetailOpen(true);
                                }}
                                style={{
                                  textAlign: "left",
                                  border: `1px solid ${isSelected ? "var(--ac)" : mapped ? confidenceTone(mapping) : "var(--b0)"}`,
                                  background: mapped ? "var(--s3)" : "var(--s1)",
                                  boxShadow: isSelected ? "0 0 0 1px var(--ac-r)" : "none",
                                  borderRadius: 8,
                                  padding: 9,
                                  color: "var(--t2)",
                                  cursor: "pointer",
                                  minWidth: 0,
                                  width: "100%",
                                  boxSizing: "border-box",
                                }}
                              >
                                <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                                  <span className="mono" style={{ color: mapped ? confidenceTone(mapping) : "var(--t3)", fontSize: 11 }}>{key}</span>
                                  {mapped && <span className="mono" style={{ color: confidenceTone(mapping), fontSize: 11 }}>{mapping.confidence_score}%</span>}
                                </div>
                                <div style={{ fontSize: 12, color: "var(--t1)", marginTop: 4, lineHeight: 1.3 }}>{technique.name}</div>
                                {otherTacticCount > 0 && (
                                  <div style={{ marginTop: 7, display: "inline-flex", color: "var(--t3)", border: "1px solid var(--b1)", borderRadius: 999, padding: "2px 6px", fontSize: 10, background: "var(--s2)" }}>
                                    Also in {otherTacticCount}
                                  </div>
                                )}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div
            style={{
              width: detailOpen && selected ? 380 : 0,
              flexShrink: 0,
              minHeight: 0,
              overflow: "hidden",
              transition: "width 180ms ease",
            }}
          >
            <div
              style={{
                width: 380,
                maxWidth: "100%",
                height: "100%",
                display: "flex",
                alignItems: "flex-start",
                opacity: detailOpen && selected ? 1 : 0,
                transform: detailOpen && selected ? "translateX(0)" : "translateX(24px)",
                transition: "transform 180ms ease, opacity 180ms ease",
                pointerEvents: detailOpen && selected ? "auto" : "none",
              }}
            >
              {selected ? (
                <TechniqueDetail
                  selected={selected}
                  mappings={mappings}
                  mappingsByTechnique={mappingsByTechnique}
                  canWrite={canWrite}
                  onClose={() => setDetailOpen(false)}
                  onAdd={addMapping}
                  onDelete={(mapping) => deleteMutation.mutate({ incidentId, linkId: mapping.id })}
                />
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </Modal>
  );
}

function TechniqueDetail({ selected, mappings, mappingsByTechnique, canWrite, onClose, onAdd, onDelete }) {
  const mapping = selected?.mapping;
  const technique = selected?.technique;
  const tactic = selected?.tactic;
  const appearsIn = Array.isArray(technique?.appears_in_tactics_details) ? technique.appears_in_tactics_details : [];
  const relatedMappings = mappingsByTechnique.get(techniqueKey(technique)) || [];
  return (
    <div className="scrollbar-thin" style={{ border: "1px solid var(--b1)", borderRadius: 10, padding: 16, overflow: "auto", minWidth: 0, maxHeight: "min(680px, 100%)", width: "100%", background: "var(--s2)", boxShadow: "var(--el-1)" }}>
      <div style={{ display: "flex", alignItems: "start", justifyContent: "space-between", gap: 12 }}>
        <div className="mono" style={{ color: mapping ? confidenceTone(mapping) : "var(--t3)", fontSize: 12 }}>
          {technique.subtechnique_id || technique.technique_id}
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close technique detail"
          style={{ border: "none", background: "transparent", color: "var(--t3)", cursor: "pointer", padding: 3 }}
        >
          <X size={16} weight="bold" />
        </button>
      </div>
      <div style={{ color: "var(--t1)", fontWeight: 850, fontSize: 18, marginTop: 4 }}>{technique.name}</div>
      <div style={{ color: "var(--t3)", fontSize: 12, marginTop: 4 }}>Current tactic: {tactic.name} / {tactic.tactic_id}</div>
      {appearsIn.length > 1 && (
        <div style={{ marginTop: 12, padding: 10, border: "1px solid var(--b1)", borderRadius: 8, background: "var(--s1)" }}>
          <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase" }}>Multi-tactic technique</div>
          <div style={{ color: "var(--t2)", fontSize: 12, lineHeight: 1.5, marginTop: 5 }}>
            This technique is associated with multiple ATT&CK tactics. This card is shown under {tactic.name} because MITRE links it to this tactic.
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
            {appearsIn.map((item) => (
              <span key={item.tactic_id} className="mono" style={{ color: item.tactic_id === tactic.tactic_id ? "var(--ac-h)" : "var(--t3)", border: "1px solid var(--b1)", borderRadius: 999, padding: "3px 7px", fontSize: 10, background: "var(--s2)" }}>
                {item.name || item.short_name || item.tactic_id}
              </span>
            ))}
          </div>
        </div>
      )}
      <p style={{ color: "var(--t2)", fontSize: 13, lineHeight: 1.6, marginTop: 14 }}>
        {technique.description || "No local ATT&CK description available. Run MITRE sync to load official descriptions."}
      </p>
      {mapping ? (
        <div style={{ display: "grid", gap: 12, marginTop: 14 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
            <div style={{ color: confidenceTone(mapping), fontWeight: 800 }}>{mapping.confidence_score}% confidence - {mapping.mapping_source}</div>
            {canWrite && <Button variant="danger" onClick={() => onDelete(mapping)}><Trash size={14} /> Remove</Button>}
          </div>
          <div>
            <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase" }}>Reason</div>
            <div style={{ color: "var(--t2)", fontSize: 13, marginTop: 5 }}>{mapping.reason || "No reason stored."}</div>
          </div>
          <div>
            <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase" }}>Matched Evidence</div>
            <div style={{ color: "var(--t2)", fontSize: 13, marginTop: 5 }}>{(mapping.matched_evidence_ids || []).length} evidence item(s)</div>
          </div>
          {relatedMappings.length > 1 && (
            <div>
              <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase" }}>Incident mappings for this technique</div>
              <div style={{ display: "grid", gap: 5, marginTop: 6 }}>
                {relatedMappings.map((item) => (
                  <div key={item.id} style={{ color: item.tactic_id === tactic.tactic_id ? "var(--ac-h)" : "var(--t3)", fontSize: 12 }}>
                    {item.technique_id}{item.subtechnique_id ? ` / ${item.subtechnique_id}` : ""} under {item.tactic_name || item.tactic_id} - {item.confidence_score}%
                  </div>
                ))}
              </div>
            </div>
          )}
          <pre className="mono scrollbar-thin" style={{ maxHeight: 180, overflow: "auto", whiteSpace: "pre-wrap", background: "var(--s1)", border: "1px solid var(--b1)", borderRadius: 8, padding: 10, color: "var(--t2)" }}>
            {JSON.stringify(mapping.matched_fields || {}, null, 2)}
          </pre>
        </div>
      ) : (
        <div style={{ display: "grid", gap: 10, marginTop: 14 }}>
          <div style={{ color: "var(--t3)", fontSize: 13 }}>This technique is not mapped to the incident.</div>
          {canWrite && <Button variant="secondary" onClick={() => onAdd({ tactic, technique })}>Add analyst mapping</Button>}
        </div>
      )}
      {technique.attack_url && (
        <a href={technique.attack_url} target="_blank" rel="noreferrer" style={{ display: "inline-flex", marginTop: 14, color: "var(--ac-h)", fontSize: 13 }}>
          Official ATT&CK page
        </a>
      )}
      {!!mappings.length && (
        <div style={{ marginTop: 20, color: "var(--t3)", fontSize: 11 }}>
          Incident has {mappings.length} mapped ATT&CK technique{mappings.length === 1 ? "" : "s"}.
        </div>
      )}
    </div>
  );
}

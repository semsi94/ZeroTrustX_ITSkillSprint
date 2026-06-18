import { useEffect, useRef, useState } from "react";
import { WarningCircle as AlertCircle, Check, Shield } from "@phosphor-icons/react";
import IntegrationGate from "./IntegrationGate";
import { useBlockIp } from "../hooks/queries/useResponseQueries";

export default function ContainmentButton({ incidentId, targetIp, alias, onDone }) {
  const [phase, setPhase] = useState("idle");
  const [countdown, setCountdown] = useState(3);
  const [reason, setReason] = useState("");
  const [result, setResult] = useState(null);
  const timerRef = useRef(null);
  const blockMutation = useBlockIp();

  useEffect(() => () => clearTimeout(timerRef.current), []);

  function startConfirm() {
    setPhase("confirming");
    setReason("");
    let count = 3;
    setCountdown(count);
    const tick = () => {
      count -= 1;
      if (count <= 0) {
        setPhase("idle");
        return;
      }
      setCountdown(count);
      timerRef.current = setTimeout(tick, 1000);
    };
    timerRef.current = setTimeout(tick, 1000);
  }

  function cancel() {
    clearTimeout(timerRef.current);
    setPhase("idle");
  }

  async function execute() {
    clearTimeout(timerRef.current);
    if (!reason.trim()) return;
    setPhase("executing");
    try {
      await blockMutation.mutateAsync({
        ip: targetIp,
        alias,
        incident_id: incidentId && incidentId !== "standalone" ? incidentId : null,
        reason: reason.trim(),
      });
      setResult({ ok: true, msg: `Blocked ${targetIp}` });
      onDone?.();
    } catch (e) {
      const msg = e?.message || "Failed";
      setResult({ ok: false, msg: `Failed - ${msg}` });
    }
    setPhase("done");
    timerRef.current = setTimeout(() => {
      setPhase("idle");
      setResult(null);
    }, 3000);
  }

  const base = {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    borderRadius: 5,
    cursor: "pointer",
    fontSize: 12,
    fontWeight: 500,
    padding: "5px 10px",
    fontFamily: "var(--sans)",
    transition: "background 80ms",
    border: "none",
  };

  return (
    <IntegrationGate
      service="pfsense"
      fallback={
        <button disabled style={{ ...base, background: "rgba(71,85,105,0.12)", color: "var(--t3)", cursor: "not-allowed", border: "1px solid transparent" }}>
          <Shield size={13} /> Block IP
        </button>
      }
    >
      {phase === "idle" && (
        <button
          onClick={startConfirm}
          style={{ ...base, background: "rgba(220,38,38,0.12)", color: "var(--crit)", border: "1px solid rgba(220,38,38,0.25)" }}
        >
          <Shield size={13} /> Block IP
        </button>
      )}

      {phase === "confirming" && (
        <div style={{ display: "inline-flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason required"
            style={{
              height: 30,
              minWidth: 190,
              background: "var(--s1)",
              border: "1px solid var(--b0)",
              borderRadius: 6,
              color: "var(--t1)",
              padding: "0 9px",
              fontSize: 12,
              fontFamily: "var(--font)",
            }}
          />
          <button onClick={cancel} style={{ ...base, background: "var(--s1)", color: "var(--t2)", border: "1px solid var(--b0)" }}>
            Cancel
          </button>
          <button
            onClick={execute}
            disabled={!reason.trim()}
            style={{
              ...base,
              background: reason.trim() ? "rgba(220,38,38,0.85)" : "rgba(71,85,105,0.25)",
              color: "#fff",
              border: "1px solid rgba(220,38,38,0.50)",
              fontWeight: 600,
              cursor: reason.trim() ? "pointer" : "not-allowed",
            }}
          >
            Block in {countdown}s
          </button>
        </div>
      )}

      {phase === "executing" && (
        <button disabled style={{ ...base, background: "rgba(202,138,4,0.12)", color: "var(--med)", border: "1px solid rgba(202,138,4,0.25)", cursor: "wait" }}>
          <span className="pulse-dot" style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--med)", display: "inline-block" }} />
          Executing...
        </button>
      )}

      {phase === "done" && result && (
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          fontSize: 12,
          fontWeight: 500,
          color: result.ok ? "var(--low)" : "var(--crit)",
          background: result.ok ? "rgba(22,163,74,0.10)" : "rgba(220,38,38,0.10)",
          border: `1px solid ${result.ok ? "rgba(22,163,74,0.25)" : "rgba(220,38,38,0.25)"}`,
          padding: "5px 10px",
          borderRadius: 5,
        }}>
          {result.ok ? <Check size={12} /> : <AlertCircle size={12} />}
          {result.msg}
        </span>
      )}
    </IntegrationGate>
  );
}

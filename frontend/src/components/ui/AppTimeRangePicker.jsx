import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Clock, CaretDown } from "@phosphor-icons/react";
import Input from "./Input";
import Button from "./Button";

export const PRESET_TIME_RANGES = [
  { label: "Last 15 minutes", earliest: "-15m", latest: "now" },
  { label: "Last 1 hour", earliest: "-1h", latest: "now" },
  { label: "Last 4 hours", earliest: "-4h", latest: "now" },
  { label: "Last 24 hours", earliest: "-24h", latest: "now" },
  { label: "Last 7 days", earliest: "-7d", latest: "now" },
  { label: "Last 30 days", earliest: "-30d", latest: "now" },
  { label: "Last 90 days", earliest: "-90d", latest: "now" },
  { label: "All time", earliest: "0", latest: "now" },
];

export function defaultTimeRange() {
  return PRESET_TIME_RANGES[3];
}

export default function AppTimeRangePicker({ value, onChange }) {
  const current = value || defaultTimeRange();
  const [open, setOpen] = useState(false);
  const [relativeValue, setRelativeValue] = useState(24);
  const [relativeUnit, setRelativeUnit] = useState("h");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [earliest, setEarliest] = useState(current.earliest || "-24h");
  const [latest, setLatest] = useState(current.latest || "now");
  const ref = useRef(null);
  const popoverRef = useRef(null);
  const [popoverStyle, setPopoverStyle] = useState(null);

  useEffect(() => {
    function onDoc(event) {
      if (ref.current?.contains(event.target) || popoverRef.current?.contains(event.target)) return;
      setOpen(false);
    }
    function onKey(event) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  useLayoutEffect(() => {
    if (!open) return undefined;

    function updatePosition() {
      if (!ref.current) return;
      const rect = ref.current.getBoundingClientRect();
      const viewportPadding = 16;
      const preferredWidth = Math.min(520, window.innerWidth - (viewportPadding * 2));
      const left = Math.min(rect.left, Math.max(viewportPadding, window.innerWidth - preferredWidth - viewportPadding));
      const maxHeight = Math.max(280, window.innerHeight - rect.bottom - viewportPadding - 8);
      setPopoverStyle({
        position: "fixed",
        top: rect.bottom + 6,
        left,
        width: preferredWidth,
        maxWidth: preferredWidth,
        maxHeight,
        zIndex: "var(--z-popover)",
      });
    }

    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition, true);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition, true);
    };
  }, [open]);

  const relativeLabel = useMemo(() => {
    const units = { m: "minutes", h: "hours", d: "days", w: "weeks", mon: "months" };
    return `Last ${relativeValue || 1} ${units[relativeUnit]}`;
  }, [relativeValue, relativeUnit]);

  function apply(next) {
    onChange?.(next);
    setOpen(false);
  }

  return (
    <div ref={ref} style={{ position: "relative", width: "100%" }}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          width: "100%",
          minHeight: 36,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 10,
          background: "var(--s1)",
          border: `1px solid ${open ? "var(--b3)" : "var(--b0)"}`,
          boxShadow: open ? "inset 0 1px 3px rgba(0,0,0,0.28)" : "none",
          borderRadius: 6,
          color: "var(--t1)",
          fontSize: 13,
          padding: "8px 10px",
          cursor: "pointer",
          fontFamily: "var(--font-sans)",
        }}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <Clock size={14} color="var(--t3)" weight="regular" />
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{current.label}</span>
        </span>
        <CaretDown size={15} color="var(--t3)" weight="regular" />
      </button>

      {open && popoverStyle && createPortal(
        <div
          ref={popoverRef}
          className="scrollbar-thin"
          style={{
            ...popoverStyle,
            overflow: "auto",
            background: "var(--s2)",
            border: "1px solid var(--b1)",
            borderRadius: 10,
            boxShadow: "var(--el-2)",
            padding: 12,
          }}
        >
          <PickerSection title="Quick Presets">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
              {PRESET_TIME_RANGES.map((preset) => (
                <button key={preset.label} type="button" onClick={() => apply(preset)} style={optionStyle(current.label === preset.label)}>
                  {preset.label}
                </button>
              ))}
            </div>
          </PickerSection>

          <PickerSection title="Relative">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr auto", gap: 8, alignItems: "center" }}>
              <Input type="number" min="1" value={relativeValue} onChange={(e) => setRelativeValue(e.target.value)} />
              <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 4 }}>
                {[
                  ["m", "min"],
                  ["h", "hr"],
                  ["d", "day"],
                  ["w", "wk"],
                  ["mon", "mo"],
                ].map(([value, label]) => (
                  <button key={value} type="button" onClick={() => setRelativeUnit(value)} style={unitButtonStyle(relativeUnit === value)}>
                    {label}
                  </button>
                ))}
              </div>
              <Button variant="secondary" onClick={() => apply({ label: relativeLabel, earliest: `-${relativeValue || 1}${relativeUnit}`, latest: "now" })}>Apply</Button>
            </div>
          </PickerSection>

          <PickerSection title="Absolute">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 8, alignItems: "center" }}>
              <Input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
              <Input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
              <Button
                variant="secondary"
                disabled={!start || !end || new Date(start) >= new Date(end)}
                onClick={() => apply({ label: "Custom absolute", earliest: new Date(start).toISOString(), latest: new Date(end).toISOString() })}
              >
                Apply
              </Button>
            </div>
          </PickerSection>

          <PickerSection title="Splunk Format">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr auto", gap: 8, alignItems: "center" }}>
              <Input value={earliest} onChange={(e) => setEarliest(e.target.value)} placeholder="-24h" />
              <Input value={latest} onChange={(e) => setLatest(e.target.value)} placeholder="now" />
              <Button variant="secondary" onClick={() => apply({ label: `${earliest} to ${latest}`, earliest, latest })}>Apply</Button>
            </div>
            <div style={{ color: "var(--t3)", fontSize: 11, marginTop: 6 }}>Examples: -24h, -7d@d, now, 0</div>
          </PickerSection>
        </div>,
        document.body
      )}
    </div>
  );
}

function PickerSection({ title, children }) {
  return (
    <section style={{ paddingBottom: 12, marginBottom: 12, borderBottom: "1px solid var(--b0)" }}>
      <div style={{ color: "var(--t3)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.07em", fontWeight: 700, marginBottom: 8 }}>{title}</div>
      {children}
    </section>
  );
}

function optionStyle(active) {
  return {
    border: `1px solid ${active ? "var(--b3)" : "var(--b0)"}`,
    background: active ? "var(--ac-d)" : "var(--s1)",
    boxShadow: "none",
    color: "var(--t2)",
    borderRadius: 6,
    padding: "8px 10px",
    textAlign: "left",
    cursor: "pointer",
    fontSize: 13,
  };
}

function unitButtonStyle(active) {
  return {
    border: `1px solid ${active ? "var(--b3)" : "var(--b0)"}`,
    background: active ? "var(--ac-d)" : "var(--s1)",
    boxShadow: "none",
    color: "var(--t2)",
    borderRadius: 6,
    padding: "8px 6px",
    cursor: "pointer",
    fontSize: 12,
  };
}

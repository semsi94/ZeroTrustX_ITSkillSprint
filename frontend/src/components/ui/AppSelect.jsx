import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, CaretDown } from "@phosphor-icons/react";

export default function AppSelect({
  value,
  onChange,
  options = [],
  placeholder = "Select",
  disabled = false,
  style = {},
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const menuRef = useRef(null);
  const [menuStyle, setMenuStyle] = useState(null);
  const selected = options.find((o) => o.value === value);

  useEffect(() => {
    function onDoc(event) {
      if (ref.current?.contains(event.target) || menuRef.current?.contains(event.target)) return;
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
      const vp = 16;
      const width = Math.max(rect.width, 180);
      const availRight = window.innerWidth - vp;
      const left = Math.min(rect.left, Math.max(vp, availRight - width));
      setMenuStyle({
        position: "fixed",
        top: rect.bottom + 4,
        left,
        width,
        maxWidth: Math.max(180, window.innerWidth - vp * 2),
        zIndex: "var(--z-dropdown)",
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

  return (
    <div ref={ref} style={{ position: "relative", width: "100%", ...style }}>
      <button
        type="button"
        disabled={disabled}
        onClick={() => !disabled && setOpen((v) => !v)}
        style={{
          width: "100%",
          minHeight: 34,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
          background: "var(--s1)",
          border: `1px solid ${open ? "var(--b3)" : "var(--b1)"}`,
          boxShadow: open ? "0 0 0 3px var(--ac-r)" : "none",
          borderRadius: "var(--r-md)",
          color: selected ? "var(--t1)" : "var(--t3)",
          fontSize: 13,
          padding: "7px 10px",
          cursor: disabled ? "not-allowed" : "pointer",
          fontFamily: "var(--font-sans)",
          textAlign: "left",
          transition: "border-color var(--t-fast) var(--ease), box-shadow var(--t-fast) var(--ease)",
          opacity: disabled ? 0.5 : 1,
        }}
      >
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {selected?.label || placeholder}
        </span>
        <CaretDown size={12} weight="bold" color="var(--t3)" style={{ flexShrink: 0 }} />
      </button>

      {open && menuStyle && createPortal(
        <div
          ref={menuRef}
          className="scrollbar-thin"
          style={{
            ...menuStyle,
            maxHeight: 260,
            overflow: "auto",
            background: "var(--s2)",
            border: "1px solid var(--b2)",
            borderRadius: "var(--r-lg)",
            boxShadow: "var(--el-2)",
            padding: 4,
          }}
        >
          {options.map((opt) => (
            <button
              key={opt.value}
              type="button"
              disabled={opt.disabled}
              onClick={() => {
                onChange?.(opt.value);
                setOpen(false);
              }}
              style={{
                width: "100%",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
                border: "none",
                borderRadius: "var(--r-md)",
                background: opt.value === value ? "var(--ac-d)" : "transparent",
                color: opt.disabled ? "var(--t4)" : opt.value === value ? "var(--ac-h)" : "var(--t1)",
                fontSize: 13,
                padding: "7px 10px",
                cursor: opt.disabled ? "not-allowed" : "pointer",
                textAlign: "left",
                fontFamily: "var(--font-sans)",
                transition: "background var(--t-fast) var(--ease)",
              }}
              onMouseEnter={(e) => {
                if (opt.value !== value && !opt.disabled)
                  e.currentTarget.style.background = "var(--s3)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background =
                  opt.value === value ? "var(--ac-d)" : "transparent";
              }}
            >
              <span>{opt.label}</span>
              {opt.value === value && (
                <Check size={12} weight="bold" color="var(--ac-h)" />
              )}
            </button>
          ))}
        </div>,
        document.body
      )}
    </div>
  );
}

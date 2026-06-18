import { useEffect } from "react";
import { createPortal } from "react-dom";
import { X } from "@phosphor-icons/react";

export default function Modal({
  open,
  onClose,
  title,
  children,
  maxWidth = 560,
  maxHeight = "calc(100vh - 48px)",
  width = "min(100%, calc(100vw - 48px))",
  height = "auto",
  zIndex = 5000,
  contentStyle,
  bodyStyle,
}) {
  const resolvedMaxWidth = typeof maxWidth === "number" ? `${maxWidth}px` : maxWidth;
  const resolvedMaxHeight = typeof maxHeight === "number" ? `${maxHeight}px` : maxHeight;

  useEffect(() => {
    if (!open) return undefined;
    const previousOverflow = document.body.style.overflow;
    const previousHtmlOverflow = document.documentElement.style.overflow;
    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";
    const onKeyDown = (event) => {
      if (event.key === "Escape" && onClose) onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.documentElement.style.overflow = previousHtmlOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onClose]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div
      onClick={onClose || (() => {})}
      aria-modal="true"
      role="dialog"
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(5,7,12,0.75)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex,
        padding: 24,
        animation: "pageIn var(--t-base) var(--ease) both",
        overflow: "hidden",
        overscrollBehavior: "contain",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="scrollbar-thin modal-enter"
        style={{
          background: "var(--s2)",
          border: "1px solid var(--b2)",
          borderRadius: "var(--r-lg)",
          boxShadow: "var(--el-modal)",
          width,
          height,
          maxWidth: `min(${resolvedMaxWidth}, calc(100vw - 48px))`,
          maxHeight: `min(${resolvedMaxHeight}, calc(100vh - 48px))`,
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          minWidth: 0,
          minHeight: 0,
          position: "relative",
          ...contentStyle,
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "13px 20px",
            background: "var(--s1)",
            borderBottom: "1px solid var(--b1)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexShrink: 0,
          }}
        >
          <div style={{ fontWeight: 600, fontSize: 13, color: "var(--t1)", letterSpacing: "-0.01em" }}>
            {title}
          </div>
          <button
            onClick={onClose || (() => {})}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--t3)",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: 4,
              borderRadius: "var(--r-sm)",
              width: 26,
              height: 26,
              transition: "color var(--t-fast) var(--ease), background var(--t-fast) var(--ease)",
              marginRight: -4,
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = "var(--t1)";
              e.currentTarget.style.background = "var(--s3)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = "var(--t3)";
              e.currentTarget.style.background = "transparent";
            }}
          >
            <X size={14} weight="bold" />
          </button>
        </div>

        {/* Body */}
        <div
          className="scrollbar-thin"
          style={{
            padding: 20,
            overflow: "auto",
            minHeight: 0,
            flex: 1,
            overscrollBehavior: "contain",
            ...bodyStyle,
          }}
        >
          {children}
        </div>
      </div>
    </div>,
    document.body,
  );
}

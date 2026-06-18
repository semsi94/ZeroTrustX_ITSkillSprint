import { useRef, useState } from "react";

export default function Tooltip({ content, children, delay = 0 }) {
  const [show, setShow] = useState(false);
  const timer = useRef(null);

  function handleEnter() {
    if (delay > 0) {
      timer.current = setTimeout(() => setShow(true), delay);
    } else {
      setShow(true);
    }
  }

  function handleLeave() {
    clearTimeout(timer.current);
    setShow(false);
  }

  return (
    <span
      style={{ position: "relative", display: "inline-block" }}
      onMouseEnter={handleEnter}
      onMouseLeave={handleLeave}
    >
      {children}
      {show && content && (
        <span
          style={{
            position: "absolute",
            bottom: "calc(100% + 6px)",
            left: "50%",
            transform: "translateX(-50%)",
            background: "var(--s3)",
            border: "1px solid var(--b2)",
            borderRadius: "var(--r-md)",
            padding: "5px 10px",
            fontSize: 11,
            color: "var(--t1)",
            whiteSpace: "nowrap",
            zIndex: 1200,
            boxShadow: "var(--el-2)",
            pointerEvents: "none",
          }}
        >
          {content}
          <span style={{
            position: "absolute",
            top: "100%",
            left: "50%",
            transform: "translateX(-50%)",
            width: 0, height: 0,
            borderLeft: "5px solid transparent",
            borderRight: "5px solid transparent",
            borderTop: "5px solid var(--b2)",
          }} />
        </span>
      )}
    </span>
  );
}

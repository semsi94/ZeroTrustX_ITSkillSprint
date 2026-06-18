import { useEffect, useRef, useState } from "react";

function colorFor(score) {
  if (score <= 30) return "var(--low)";
  if (score <= 60) return "var(--med)";
  return "var(--crit)";
}

/** ease-out-cubic easing function */
function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

export default function CIAGauge({ label, score = 0, size = 120 }) {
  const target = Math.max(0, Math.min(100, score));
  const [displayed, setDisplayed] = useState(0);
  const rafRef = useRef(null);
  const startRef = useRef(null);
  const fromRef = useRef(0);

  useEffect(() => {
    // Cancel any in-progress animation
    if (rafRef.current) cancelAnimationFrame(rafRef.current);

    const from = fromRef.current;
    const to = target;
    const duration = 700; // ms

    startRef.current = null;

    function tick(now) {
      if (!startRef.current) startRef.current = now;
      const elapsed = now - startRef.current;
      const progress = Math.min(elapsed / duration, 1);
      const eased = easeOutCubic(progress);
      const current = from + (to - from) * eased;

      fromRef.current = current;
      setDisplayed(current);

      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else {
        fromRef.current = to;
        setDisplayed(to);
      }
    }

    rafRef.current = requestAnimationFrame(tick);
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current); };
  }, [target]);

  const color = colorFor(target); // use target color so it doesn't flicker mid-animation

  const radius = 50;
  const strokeWidth = 10;
  const circumference = Math.PI * radius; // half-circle arc length
  const offset = circumference - (displayed / 100) * circumference;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 6,
        flex: 1,
        overflow: "visible",
        paddingBottom: 4,
      }}
    >
      <div style={{ position: "relative", width: size, height: size / 2 + 10 }}>
        <svg
          width={size}
          height={size / 2 + 10}
          viewBox="0 0 120 70"
          style={{ overflow: "visible" }}
        >
          {/* track */}
          <path
            d="M 10 60 A 50 50 0 0 1 110 60"
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* fill */}
          <path
            d="M 10 60 A 50 50 0 0 1 110 60"
            fill="none"
            stroke={color}
            opacity={0.95}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div
          style={{
            position: "absolute",
            top: 24,
            left: 0,
            right: 0,
            textAlign: "center",
            color: "var(--t1)",
            fontSize: 22,
            fontWeight: 700,
            fontFamily: "var(--font-mono)",
          }}
        >
          {Math.round(displayed)}
        </div>
      </div>
      <div
        style={{
          fontSize: 11,
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          color: "var(--t3)",
          whiteSpace: "nowrap",
          textAlign: "center",
        }}
      >
        {label}
      </div>
    </div>
  );
}

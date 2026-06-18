import { useCallback } from "react";

/**
 * Material-style ripple on click. Spawns a transient `<span>` at the click
 * coordinate inside the target button; CSS animation removes itself after
 * 500ms. Caller is responsible for `position: relative; overflow: hidden`
 * on the host button — this hook applies them defensively too.
 *
 * Usage:
 *   const ripple = useRipple();
 *   <button onClick={(e) => { ripple(e); doThing(e); }}>...</button>
 */
export function useRipple() {
  return useCallback((e) => {
    const btn = e.currentTarget;
    if (!btn) return;
    const rect = btn.getBoundingClientRect();
    const ripple = document.createElement("span");
    ripple.className = "ripple-effect";
    ripple.style.left = `${e.clientX - rect.left - 30}px`;
    ripple.style.top  = `${e.clientY - rect.top  - 30}px`;
    // Defensive — ensure host can clip the ripple
    if (getComputedStyle(btn).position === "static") {
      btn.style.position = "relative";
    }
    btn.style.overflow = "hidden";
    btn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 500);
  }, []);
}

export default useRipple;

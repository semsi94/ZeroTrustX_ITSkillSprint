import { useEffect, useRef, useState } from "react";

/**
 * Fires a one-shot boolean flag whenever `value` changes after the initial mount.
 * Resets the flag after `duration` ms.
 *
 * Usage:
 *   const changed = useValueChange(severity, 300);
 *   <span className={changed ? "badge-updated" : ""} />
 */
export function useValueChange(value, duration = 300) {
  const prevRef = useRef(value);
  const [changed, setChanged] = useState(false);

  useEffect(() => {
    if (prevRef.current !== value && prevRef.current !== undefined) {
      setChanged(true);
      const t = setTimeout(() => setChanged(false), duration);
      return () => clearTimeout(t);
    }
    prevRef.current = value;
  }, [value, duration]);

  return changed;
}

const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
  info: 4,
  unknown: 5,
};

const STATUS_ORDER = {
  draft: 0,
  pending_evidence: 1,
  pending_approval: 2,
  new: 3,
  triage: 4,
  investigating: 5,
  contained: 6,
  monitoring: 7,
  resolved: 8,
  closed: 9,
  rejected: 10,
  open: 11,
  assigned: 12,
  in_progress: 13,
  waiting: 14,
  escalated: 15,
  cancelled: 16,
  success: 17,
  failed: 18,
};

function normalize(value) {
  if (value === null || value === undefined || value === "") return "";
  return String(value).toLowerCase().replace(/\s+/g, "_");
}

function timeValue(value) {
  const t = new Date(value || 0).getTime();
  return Number.isNaN(t) ? 0 : t;
}

function compareValue(a, b, key) {
  const lowerKey = String(key || "").toLowerCase();
  if (lowerKey.includes("severity") || lowerKey.includes("priority") || lowerKey === "level") {
    return (SEVERITY_ORDER[normalize(a)] ?? SEVERITY_ORDER.unknown) - (SEVERITY_ORDER[normalize(b)] ?? SEVERITY_ORDER.unknown);
  }
  if (lowerKey.includes("status") || lowerKey.includes("state")) {
    return (STATUS_ORDER[normalize(a)] ?? 99) - (STATUS_ORDER[normalize(b)] ?? 99);
  }
  if (lowerKey.includes("time") || lowerKey.includes("date") || lowerKey.includes("_at") || lowerKey.includes("run")) {
    return timeValue(a) - timeValue(b);
  }
  if (typeof a === "number" || typeof b === "number") {
    return (Number(a) || 0) - (Number(b) || 0);
  }
  return String(a ?? "").localeCompare(String(b ?? ""), undefined, { numeric: true, sensitivity: "base" });
}

export function nextSort(current, key) {
  if (current?.key !== key) return { key, direction: "asc" };
  return { key, direction: current.direction === "asc" ? "desc" : "asc" };
}

export function sortIndicator(sort, key) {
  if (sort?.key !== key) return "↕";
  return sort.direction === "asc" ? "↑" : "↓";
}

export function sortRows(rows, sort, accessors = {}) {
  const list = Array.isArray(rows) ? rows : [];
  if (!sort?.key) return list;
  const accessor = accessors[sort.key] || ((row) => row?.[sort.key]);
  return list
    .map((row, index) => ({ row, index }))
    .sort((a, b) => {
      const diff = compareValue(accessor(a.row), accessor(b.row), sort.key);
      const stable = diff === 0 ? a.index - b.index : diff;
      return sort.direction === "desc" ? -stable : stable;
    })
    .map((item) => item.row);
}

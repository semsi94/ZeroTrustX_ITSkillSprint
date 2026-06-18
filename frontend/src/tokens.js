// Design tokens — Neo-Industrial Dark system
// All CSS var references map through the :root aliases in index.css

export const colors = {
  bgBase:      "var(--s0)",
  bgSurface:   "var(--s2)",
  bgElevated:  "var(--s3)",
  bgHover:     "var(--s3)",
  bgSelected:  "var(--ac-d)",
  borderDim:   "var(--b0)",
  borderDefault: "var(--b1)",
  borderFocus: "var(--ac-r)",
  accent:      "var(--ac)",
  accentBright: "var(--ac-h)",
  accentDim:   "var(--ac-d)",
  accentGlow:  "var(--ac-d)",
  crit:  "var(--crit)", high: "var(--high)",
  med:   "var(--med)",  low:  "var(--low)",  info: "var(--info)",
  text1: "var(--t1)", text2: "var(--t2)", text3: "var(--t3)", text4: "var(--t4)",
};

export const severityMeta = {
  5: { label: "Critical", color: "var(--crit)", bg: "var(--crit-d)" },
  4: { label: "High",     color: "var(--high)", bg: "var(--high-d)" },
  3: { label: "Medium",   color: "var(--med)",  bg: "var(--med-d)"  },
  2: { label: "Low",      color: "var(--low)",  bg: "var(--low-d)"  },
  1: { label: "Info",     color: "var(--info)", bg: "var(--info-d)" },
};

export const statusMeta = {
  draft:              { label: "Draft",            color: "var(--t3)"          },
  pending_evidence:   { label: "Pending Evidence", color: "var(--st-new)"      },
  pending_approval:   { label: "Pending Approval", color: "var(--st-triage)"   },
  active:             { label: "Active",           color: "var(--st-new)"      },
  new:                { label: "New",              color: "var(--st-new)"      },
  triage:             { label: "Triage",           color: "var(--st-triage)"   },
  in_review:          { label: "In Review",        color: "var(--st-triage)"   },
  investigating:      { label: "Investigating",    color: "var(--st-invest)"   },
  contained:          { label: "Contained",        color: "var(--st-contain)"  },
  resolved:           { label: "Resolved",         color: "var(--st-closed)"   },
  monitoring:         { label: "Monitoring",       color: "var(--st-monitor)"  },
  closed:             { label: "Closed",           color: "var(--st-closed)"   },
  rejected:           { label: "Rejected",         color: "var(--crit)"        },
  undecided:          { label: "Undecided",        color: "var(--t3)"          },
  true_positive:      { label: "True Positive",    color: "var(--low)"         },
  false_positive:     { label: "False Positive",   color: "var(--t3)"          },
  benign_positive:    { label: "Benign Positive",  color: "var(--info)"        },
  duplicate:          { label: "Duplicate",        color: "var(--t3)"          },
  needs_more_evidence:{ label: "Needs Evidence",   color: "var(--med)"         },
  success:            { label: "Success",          color: "var(--low)"         },
  failed:             { label: "Failed",           color: "var(--crit)"        },
  pending:            { label: "Pending",          color: "var(--med)"         },
  reverted:           { label: "Reverted",         color: "var(--t3)"          },
};

export const sourceMeta = {
  suricata: { label: "Suricata", color: "#C07828", short: "S" },
  pfsense:  { label: "pfSense",  color: "#3D7EF5", short: "P" },
  web:      { label: "Web",      color: "#2E8F4A", short: "W" },
  windows:  { label: "Windows",  color: "#3D7EF5", short: "Wn"},
  unknown:  { label: "Unknown",  color: "var(--t3)", short: "?" },
};

export const zoneMeta = {
  dmz:        { label: "DMZ",        color: "var(--high)"    },
  internal:   { label: "Internal",   color: "var(--ac)"      },
  management: { label: "Management", color: "var(--st-monitor)" },
  internet:   { label: "Internet",   color: "var(--crit)"    },
  unknown:    { label: "Unknown",    color: "var(--t3)"      },
};

export const chartPalette = [
  "var(--crit)", "var(--high)", "var(--med)", "var(--low)", "var(--info)",
];

export const chartTooltipStyle = {
  contentStyle: {
    background: "var(--s3)",
    border: "1px solid var(--b2)",
    borderRadius: 6,
    fontSize: 12,
    padding: "8px 12px",
    boxShadow: "var(--el-2)",
    fontFamily: "Inter, sans-serif",
  },
  labelStyle: { color: "#DCE1EB", fontWeight: 600, marginBottom: 4 },
  itemStyle:  { color: "#8D99AD" },
  cursor:     { fill: "rgba(61,126,245,0.06)" },
};

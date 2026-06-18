import { useMemo, useState } from "react";
import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";

const SEVERITY_ORDER = {
  critical: 0, high: 1, medium: 2, low: 3,
  informational: 4, info: 4, unknown: 5,
};
const STATUS_ORDER = {
  draft: 0, pending_evidence: 1, pending_approval: 2,
  new: 3, triage: 4, investigating: 5, contained: 6,
  monitoring: 7, resolved: 8, closed: 9, rejected: 10,
  pending: 11, success: 12, failed: 13,
};

function normalize(value) {
  if (value === null || value === undefined || value === "") return "";
  return String(value).toLowerCase().replace(/\s+/g, "_");
}
function timeValue(value) {
  const parsed = new Date(value || 0).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
}
function compareValues(a, b, key) {
  const lowerKey = String(key || "").toLowerCase();
  if (lowerKey.includes("severity") || lowerKey === "level")
    return (SEVERITY_ORDER[normalize(a)] ?? SEVERITY_ORDER.unknown) - (SEVERITY_ORDER[normalize(b)] ?? SEVERITY_ORDER.unknown);
  if (lowerKey.includes("status") || lowerKey.includes("state"))
    return (STATUS_ORDER[normalize(a)] ?? 99) - (STATUS_ORDER[normalize(b)] ?? 99);
  if (lowerKey.includes("time") || lowerKey.includes("date") || lowerKey.includes("_at") || lowerKey.includes("run"))
    return timeValue(a) - timeValue(b);
  if (typeof a === "number" || typeof b === "number")
    return (Number(a) || 0) - (Number(b) || 0);
  return String(a ?? "").localeCompare(String(b ?? ""), undefined, { numeric: true, sensitivity: "base" });
}

function sortGlyph(column, legacySort) {
  if (legacySort) {
    if (legacySort.key !== column.id) return "↕";
    return legacySort.direction === "asc" ? "↑" : "↓";
  }
  const sorted = column.getIsSorted();
  if (sorted === "asc") return "↑";
  if (sorted === "desc") return "↓";
  return "↕";
}

export default function Table({
  columns,
  rows,
  onRowClick,
  empty = "No data",
  rowKey,
  sort,
  onSort,
  loading = false,
  error = null,
  pagination = false,
  pageSize = 10,
}) {
  const [sorting, setSorting] = useState([]);
  const data = Array.isArray(rows) ? rows : [];

  const tableColumns = useMemo(() => columns.map((col) => ({
    id: col.key,
    accessorFn: (row) => (col.accessor ? col.accessor(row) : row?.[col.key]),
    header: col.label,
    enableSorting: col.sortable !== false,
    sortingFn: (a, b, id) => compareValues(a.getValue(id), b.getValue(id), id),
    size: col.width,
    cell: (info) => (col.render ? col.render(info.row.original) : info.getValue()),
    meta: col,
  })), [columns]);

  const table = useReactTable({
    data,
    columns: tableColumns,
    state: onSort
      ? { sorting: sort?.key ? [{ id: sort.key, desc: sort.direction === "desc" }] : [] }
      : { sorting },
    onSortingChange: setSorting,
    manualSorting: Boolean(onSort),
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: onSort ? undefined : getSortedRowModel(),
    getPaginationRowModel: pagination ? getPaginationRowModel() : undefined,
    initialState: pagination ? { pagination: { pageSize } } : undefined,
  });

  const visibleRows = table.getRowModel().rows;
  const colSpan = Math.max(columns.length, 1);

  return (
    <div
      style={{
        overflow: "hidden",
        overflowX: "auto",
        background: "var(--s2)",
        border: "1px solid var(--b1)",
        borderRadius: "var(--r-lg)",
        boxShadow: "var(--el-1)",
      }}
      className="scrollbar-thin"
    >
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => {
                const meta = header.column.columnDef.meta || {};
                const canSort = header.column.getCanSort();
                const isSorted = sort?.key === header.column.id || header.column.getIsSorted();
                return (
                  <th
                    key={header.id}
                    style={{
                      background: "var(--s1)",
                      textAlign: "left",
                      color: "var(--t3)",
                      fontSize: 10,
                      letterSpacing: "0.10em",
                      padding: "8px 14px",
                      textTransform: "uppercase",
                      borderBottom: "1px solid var(--b1)",
                      fontWeight: 700,
                      width: meta.width,
                      whiteSpace: "nowrap",
                    }}
                  >
                    {canSort ? (
                      <button
                        type="button"
                        onClick={(event) => {
                          if (onSort) onSort(header.column.id);
                          else header.column.getToggleSortingHandler()?.(event);
                        }}
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 4,
                          border: "none",
                          background: "transparent",
                          color: isSorted ? "var(--ac-h)" : "inherit",
                          padding: 0,
                          cursor: "pointer",
                          font: "inherit",
                          textTransform: "inherit",
                          letterSpacing: "inherit",
                        }}
                        title={`Sort by ${header.column.columnDef.header || header.column.id}`}
                      >
                        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {flexRender(header.column.columnDef.header, header.getContext())}
                        </span>
                        <span style={{
                          color: isSorted ? "var(--ac-h)" : "var(--t4)",
                          fontSize: 10,
                          lineHeight: 1,
                        }}>
                          {sortGlyph(header.column, sort)}
                        </span>
                      </button>
                    ) : (
                      flexRender(header.column.columnDef.header, header.getContext())
                    )}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {error ? (
            <tr>
              <td colSpan={colSpan} style={{ padding: 32, textAlign: "center", color: "var(--crit)", fontSize: 13 }}>
                {error}
              </td>
            </tr>
          ) : loading ? (
            Array.from({ length: 5 }).map((_, index) => (
              <tr key={`loading-${index}`} style={{ borderBottom: "1px solid var(--b0)" }}>
                {columns.map((col, cellIndex) => (
                  <td key={col.key || cellIndex} style={{ padding: "10px 14px" }}>
                    <div className="skeleton" style={{ height: 11, width: cellIndex === 0 ? "68%" : "44%" }} />
                  </td>
                ))}
              </tr>
            ))
          ) : visibleRows.length === 0 ? (
            <tr>
              <td
                colSpan={colSpan}
                style={
                  typeof empty === "string"
                    ? { padding: 36, textAlign: "center", color: "var(--t3)", fontSize: 13 }
                    : { padding: 0 }
                }
              >
                {empty}
              </td>
            </tr>
          ) : (
            visibleRows.map((row, idx) => (
              <tr
                key={rowKey ? rowKey(row.original, idx) : row.id}
                style={{
                  borderBottom: "1px solid var(--b0)",
                  cursor: onRowClick ? "pointer" : "default",
                  transition: "background var(--t-fast) var(--ease)",
                }}
                onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                onMouseEnter={(e) => {
                  if (onRowClick) e.currentTarget.style.background = "var(--s3)";
                  else e.currentTarget.style.background = "var(--s2)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "transparent";
                }}
              >
                {row.getVisibleCells().map((cell) => {
                  const meta = cell.column.columnDef.meta || {};
                  return (
                    <td
                      key={cell.id}
                      style={{
                        padding: "10px 14px",
                        color: "var(--t1)",
                        fontSize: 12,
                        verticalAlign: "middle",
                        lineHeight: 1.4,
                        ...(meta.cellStyle || {}),
                      }}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  );
                })}
              </tr>
            ))
          )}
        </tbody>
      </table>

      {pagination && !loading && !error && data.length > pageSize && (
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          padding: "8px 14px",
          borderTop: "1px solid var(--b1)",
          color: "var(--t3)",
          fontSize: 11,
          background: "var(--s1)",
        }}>
          <span>
            Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
          </span>
          <div style={{ display: "flex", gap: 6 }}>
            <button
              type="button"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              style={pagerBtnStyle}
            >
              Previous
            </button>
            <button
              type="button"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              style={pagerBtnStyle}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

const pagerBtnStyle = {
  border: "1px solid var(--b2)",
  background: "var(--s3)",
  color: "var(--t2)",
  borderRadius: "var(--r-sm)",
  padding: "4px 10px",
  cursor: "pointer",
  fontSize: 11,
  fontFamily: "var(--font-sans)",
  boxShadow: "none",
};

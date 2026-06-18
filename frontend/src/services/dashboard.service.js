import { request } from "../api/client";

export function getDashboardSummary() {
  return request({ method: "GET", url: "/dashboard/summary" }, "Failed to load dashboard summary");
}

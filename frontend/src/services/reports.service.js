import { downloadBlob } from "../api/client";
import { getSplunkReports, runSearchFromSaved } from "./splunk.service";

export { getSplunkReports, runSearchFromSaved };

export function downloadExecutivePdf(periodDays = 30) {
  return downloadBlob(
    { method: "GET", url: "/reports/pdf", params: { period_days: periodDays } },
    "PDF generation failed",
  );
}

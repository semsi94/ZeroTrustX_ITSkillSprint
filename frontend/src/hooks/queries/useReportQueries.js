import { useMutation, useQuery } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import { downloadExecutivePdf, getSplunkReports, runSearchFromSaved } from "../../services/reports.service";

export function useReports(options = {}) {
  return useQuery({
    queryKey: queryKeys.reports.list,
    queryFn: getSplunkReports,
    staleTime: 60_000,
    ...options,
  });
}

export function useRunSplunkReport() {
  return useMutation({
    mutationFn: runSearchFromSaved,
  });
}

export function useDownloadExecutivePdf() {
  return useMutation({
    mutationFn: downloadExecutivePdf,
  });
}

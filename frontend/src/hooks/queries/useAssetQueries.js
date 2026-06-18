import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import { createAsset, getAsset, getAssets } from "../../services/assets.service";

export function useAssetsQuery(filters = {}, options = {}) {
  return useQuery({
    queryKey: queryKeys.assets.list(filters),
    queryFn: () => getAssets(filters),
    staleTime: 30_000,
    ...options,
  });
}

export function useAssetQuery(id, options = {}) {
  return useQuery({
    queryKey: queryKeys.assets.detail(id),
    queryFn: () => getAsset(id),
    enabled: Boolean(id),
    staleTime: 30_000,
    ...options,
  });
}

export function useCreateAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createAsset,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}

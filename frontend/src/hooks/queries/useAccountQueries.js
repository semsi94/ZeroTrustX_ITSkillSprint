import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../lib/queryKeys";
import {
  changePassword,
  confirmMfaSetup,
  disableMfa,
  getCurrentUser,
  getMfaStatus,
  getPreferences,
  getProfile,
  startMfaSetup,
  uploadAvatar,
  updatePreferences,
  updateProfile,
} from "../../services/account.service";

export function useCurrentUser(options = {}) {
  return useQuery({
    queryKey: queryKeys.account.currentUser,
    queryFn: getCurrentUser,
    staleTime: 60_000,
    ...options,
  });
}

export function useAccountProfile(options = {}) {
  return useQuery({
    queryKey: queryKeys.account.profile,
    queryFn: getProfile,
    staleTime: 60_000,
    ...options,
  });
}

export function useUserPreferences(options = {}) {
  return useQuery({
    queryKey: queryKeys.account.preferences,
    queryFn: getPreferences,
    staleTime: 60_000,
    ...options,
  });
}

export function useMfaStatus(options = {}) {
  return useQuery({
    queryKey: queryKeys.account.mfaStatus,
    queryFn: getMfaStatus,
    staleTime: 30_000,
    ...options,
  });
}

export function useUpdateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: updateProfile,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.account.profile });
      qc.invalidateQueries({ queryKey: queryKeys.account.currentUser });
    },
  });
}

export function useUploadAvatar() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: uploadAvatar,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.account.profile });
      qc.invalidateQueries({ queryKey: queryKeys.account.currentUser });
    },
  });
}

export function useUpdatePreferences() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: updatePreferences,
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.account.preferences }),
  });
}

export function useEnableMfa() {
  return useMutation({ mutationFn: startMfaSetup });
}

export function useConfirmMfa() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: confirmMfaSetup,
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.account.mfaStatus }),
  });
}

export function useDisableMfa() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: disableMfa,
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.account.mfaStatus }),
  });
}

export function useChangePassword() {
  return useMutation({ mutationFn: changePassword });
}

import { request } from "../api/client";

export function getCurrentUser() {
  return request({ method: "GET", url: "/auth/me" }, "Failed to load current user");
}

export function getProfile() {
  return request({ method: "GET", url: "/api/account/profile" }, "Failed to load profile");
}

export function updateProfile(payload) {
  return request({ method: "PATCH", url: "/api/account/profile", data: payload }, "Failed to update profile");
}

export function uploadAvatar(file) {
  const form = new FormData();
  form.append("file", file);
  return request(
    {
      method: "POST",
      url: "/api/account/avatar",
      data: form,
      headers: { "Content-Type": "multipart/form-data" },
    },
    "Failed to upload avatar",
  );
}

export function getPreferences() {
  return request({ method: "GET", url: "/api/account/preferences" }, "Failed to load preferences");
}

export function updatePreferences(payload) {
  return request({ method: "PATCH", url: "/api/account/preferences", data: payload }, "Failed to save preferences");
}

export function getMfaStatus() {
  return request({ method: "GET", url: "/api/auth/mfa/status" }, "Failed to load MFA status");
}

export function startMfaSetup() {
  return request({ method: "POST", url: "/api/auth/mfa/setup/start" }, "Failed to start MFA setup");
}

export function confirmMfaSetup(code) {
  return request({ method: "POST", url: "/api/auth/mfa/setup/confirm", data: { code } }, "Failed to confirm MFA");
}

export function disableMfa(payload) {
  return request({ method: "POST", url: "/api/auth/mfa/disable", data: payload }, "Failed to disable MFA");
}

export function changePassword(payload) {
  return request({ method: "POST", url: "/api/auth/password/change", data: payload }, "Failed to change password");
}

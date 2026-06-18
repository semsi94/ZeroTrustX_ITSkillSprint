import { createContext, useContext, useEffect, useState } from "react";
import { api, unwrap } from "../api/client";
import { queryClient } from "../lib/queryClient";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);
  const [authError, setAuthError] = useState("");

  async function refreshUser() {
    const token = localStorage.getItem("ztx_token");
    if (!token) {
      setUser(null);
      setReady(true);
      return null;
    }
    try {
      const res = await api.get("/auth/me");
      const data = unwrap(res);
      setUser(data || null);
      setAuthError("");
      return data;
    } catch (e) {
      if (e?.response?.status === 401) {
        localStorage.removeItem("ztx_token");
        queryClient.clear();
        setUser(null);
      }
      setAuthError(e?.response?.data?.error || e.message || "Session expired");
      return null;
    } finally {
      setReady(true);
    }
  }

  useEffect(() => {
    refreshUser();
  }, []);

  async function login(identifier, password) {
    const res = await api.post("/auth/login", {
      username_or_email: identifier,
      password,
    });
    const data = res.data || {};
    if (data.mfa_required) return data;
    if (data.access_token) {
      localStorage.setItem("ztx_token", data.access_token);
      queryClient.clear();
      setUser(data.user || null);
      setAuthError("");
    }
    return data;
  }

  async function verifyMfa(challengeToken, code, rememberDevice) {
    const res = await api.post("/api/auth/mfa/verify", {
      challenge_token: challengeToken,
      code,
      remember_device: rememberDevice,
    });
    const data = res.data || {};
    if (data.success && data.access_token) {
      localStorage.setItem("ztx_token", data.access_token);
      queryClient.clear();
      setUser(data.user || null);
      setAuthError("");
    }
    return data;
  }

  function logout() {
    localStorage.removeItem("ztx_token");
    queryClient.clear();
    setUser(null);
    window.location.href = "/login";
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        ready,
        authError,
        isSignedIn: Boolean(user),
        login,
        verifyMfa,
        refreshUser,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}

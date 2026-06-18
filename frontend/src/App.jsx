import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { IntegrationProvider } from "./context/IntegrationContext";
import Sidebar from "./components/layout/Sidebar";
import Topbar from "./components/layout/Topbar";

import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import IncidentQueue from "./pages/incidents/IncidentQueue";
import IncidentDetail from "./pages/incidents/IncidentDetail";
import Investigation from "./pages/Investigation";
import Response from "./pages/Response";
import AssetList from "./pages/assets/AssetList";
import AssetDetail from "./pages/assets/AssetDetail";
import Reports from "./pages/Reports";
import Account from "./pages/Account";
import Integrations from "./pages/settings/Integrations";

function Protected({ children }) {
  const { user, ready, isSignedIn, authError } = useAuth();
  const location = useLocation();
  if (!ready) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center",
                    height: "100vh", color: "var(--t1)" }}>
        Loading...
      </div>
    );
  }
  if (isSignedIn && authError) {
    return (
      <div style={{ display: "grid", placeItems: "center", height: "100vh", color: "var(--t2)", padding: 24 }}>
        <div style={{ maxWidth: 520, padding: 22, background: "var(--s2)", border: "1px solid var(--b2)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-2)" }}>
          <h2 style={{ margin: "0 0 8px", color: "var(--t1)" }}>Session verification failed</h2>
          <p style={{ margin: 0, color: "var(--t3)", lineHeight: 1.6 }}>{authError}</p>
        </div>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  return children;
}

function Shell({ children }) {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("ztx_sidebar_collapsed") === "true");
  const location = useLocation();

  useEffect(() => {
    localStorage.setItem("ztx_sidebar_collapsed", String(collapsed));
  }, [collapsed]);

  const sidebarWidth = collapsed ? 52 : 220;
  return (
    <div style={{ height: "100vh", background: "var(--s0)", overflow: "hidden" }}>
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((v) => !v)} />
      <div style={{ marginLeft: sidebarWidth, height: "100vh", transition: "margin-left 160ms var(--ease-out)", display: "flex", flexDirection: "column", minWidth: 0 }}>
        <Topbar />
        <main className="scrollbar-thin main-scroll" style={{ flex: 1, overflow: "auto", minWidth: 0 }}>
          {/* key forces remount on route change, triggering .page-enter animation */}
          <div key={location.pathname} className="page-enter">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <IntegrationProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/sign-up" element={<Navigate to="/login" replace />} />
          <Route
            path="*"
            element={
              <Protected>
                <Shell>
                  <Routes>
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/incidents" element={<IncidentQueue />} />
                    <Route path="/incidents/:id" element={<IncidentDetail />} />
                    <Route path="/investigation" element={<Investigation />} />
                    <Route path="/response" element={<Response />} />
                    <Route path="/tickets" element={<Navigate to="/incidents" replace />} />
                    <Route path="/firewall-response" element={<Navigate to="/response" replace />} />
                    <Route path="/assets" element={<AssetList />} />
                    <Route path="/assets/:id" element={<AssetDetail />} />
                    <Route path="/reports" element={<Reports />} />
                    <Route path="/account" element={<Account />} />
                    <Route path="/account/security" element={<Navigate to="/account" replace />} />
                    <Route path="/settings/integrations" element={<Integrations />} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Routes>
                </Shell>
              </Protected>
            }
          />
        </Routes>
      </IntegrationProvider>
    </AuthProvider>
  );
}

import { useEffect, useMemo, useState } from "react";
import { Bell, ShieldCheck, SlidersHorizontal, UserCircle as UserRound } from "@phosphor-icons/react";
import PageHeader from "../components/layout/PageHeader";
import Button from "../components/ui/Button";
import Input from "../components/ui/Input";
import { useAuth } from "../context/AuthContext";
import {
  useAccountProfile,
  useChangePassword,
  useConfirmMfa,
  useDisableMfa,
  useEnableMfa,
  useMfaStatus,
  useUpdatePreferences,
  useUpdateProfile,
  useUploadAvatar,
  useUserPreferences,
} from "../hooks/queries/useAccountQueries";

const sections = [
  { id: "profile", label: "Profile", icon: UserRound },
  { id: "security", label: "Security", icon: ShieldCheck },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "preferences", label: "Preferences", icon: SlidersHorizontal },
];

export default function Account() {
  const { user, refreshUser } = useAuth();
  const [active, setActive] = useState("profile");
  const [profile, setProfile] = useState(null);
  const [prefs, setPrefs] = useState(null);
  const [mfaSetup, setMfaSetup] = useState(null);
  const [mfaCode, setMfaCode] = useState("");
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [passwordForm, setPasswordForm] = useState({ current_password: "", new_password: "", code: "" });
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const profileQuery = useAccountProfile();
  const preferencesQuery = useUserPreferences();
  const mfaStatusQuery = useMfaStatus({ retry: 0 });
  const updateProfileMutation = useUpdateProfile();
  const uploadAvatarMutation = useUploadAvatar();
  const updatePreferencesMutation = useUpdatePreferences();
  const enableMfaMutation = useEnableMfa();
  const confirmMfaMutation = useConfirmMfa();
  const disableMfaMutation = useDisableMfa();
  const changePasswordMutation = useChangePassword();

  const profileData = profileQuery.data?.profile || profileQuery.data || null;
  const preferencesData = preferencesQuery.data?.preferences || preferencesQuery.data || null;
  const mfaStatus = mfaStatusQuery.data || null;
  const loading = profileQuery.isLoading || preferencesQuery.isLoading || mfaStatusQuery.isLoading;
  const loadError = useMemo(
    () => profileQuery.error?.message || preferencesQuery.error?.message || mfaStatusQuery.error?.message || "",
    [profileQuery.error?.message, preferencesQuery.error?.message, mfaStatusQuery.error?.message],
  );
  const busy = updateProfileMutation.isPending
    || uploadAvatarMutation.isPending
    || updatePreferencesMutation.isPending
    || enableMfaMutation.isPending
    || confirmMfaMutation.isPending
    || disableMfaMutation.isPending
    || changePasswordMutation.isPending;

  useEffect(() => {
    if (profileData) setProfile(profileData);
  }, [profileData]);

  useEffect(() => {
    if (preferencesData) setPrefs(preferencesData);
  }, [preferencesData]);

  async function saveProfile() {
    setError("");
    setMessage("");
    try {
      await updateProfileMutation.mutateAsync({
        username: profile.username,
        display_name: profile.display_name,
      });
      await refreshUser();
      setMessage("Profile updated");
    } catch (e) {
      setError(e?.message || "Failed to update profile");
    }
  }

  async function uploadAvatar(file) {
    if (!file) return;
    setError("");
    setMessage("");
    try {
      await uploadAvatarMutation.mutateAsync(file);
      await refreshUser();
      await profileQuery.refetch();
      setMessage("Avatar updated");
    } catch (e) {
      setError(e?.message || "Failed to upload avatar");
    }
  }

  async function savePrefs() {
    setError("");
    setMessage("");
    try {
      await updatePreferencesMutation.mutateAsync(prefs);
      setMessage("Preferences saved");
    } catch (e) {
      setError(e?.message || "Failed to save preferences");
    }
  }

  async function startMfaSetup() {
    setError("");
    setMessage("");
    try {
      const res = await enableMfaMutation.mutateAsync();
      setMfaSetup(res || null);
      setMessage("Scan the QR code with your authenticator app, then enter the code.");
    } catch (e) {
      setError(e?.message || "Failed to start MFA setup");
    }
  }

  async function confirmMfaSetup() {
    setError("");
    setMessage("");
    try {
      const res = await confirmMfaMutation.mutateAsync(mfaCode);
      if (!res?.success) throw new Error(res?.error || "Invalid verification code");
      setMfaSetup(null);
      setMfaCode("");
      await mfaStatusQuery.refetch();
      await refreshUser();
      setMessage("Authenticator MFA enabled");
    } catch (e) {
      setError(e?.message || "Failed to confirm MFA");
    }
  }

  async function disableMfaAction() {
    setError("");
    setMessage("");
    try {
      const res = await disableMfaMutation.mutateAsync({
        password: disablePassword,
        code: disableCode || null,
      });
      if (!res?.success) throw new Error(res?.error || "Could not disable MFA");
      setDisablePassword("");
      setDisableCode("");
      await mfaStatusQuery.refetch();
      await refreshUser();
      setMessage("Authenticator MFA disabled");
    } catch (e) {
      setError(e?.message || "Failed to disable MFA");
    }
  }

  async function changePasswordAction() {
    setError("");
    setMessage("");
    try {
      const res = await changePasswordMutation.mutateAsync(passwordForm);
      if (!res?.success) throw new Error(res?.error || "Password change failed");
      setPasswordForm({ current_password: "", new_password: "", code: "" });
      setMessage("Password changed");
    } catch (e) {
      setError(e?.message || "Failed to change password");
    }
  }

  const avatar = profile?.avatar_url || user?.avatar_url;
  const email = profile?.email || user?.email;

  return (
    <>
      <PageHeader title="Account" subtitle="Manage your profile, security, notifications, and preferences" />
      <div style={{ padding: 24, display: "grid", gridTemplateColumns: "220px minmax(0, 1fr)", gap: 18 }}>
        <aside style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: 10, alignSelf: "start" }}>
          {sections.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setActive(id)} style={{ width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", borderRadius: 8, border: `1px solid ${active === id ? "var(--b3)" : "transparent"}`, background: active === id ? "var(--ac-d)" : "transparent", color: active === id ? "var(--ac-h)" : "var(--t2)", cursor: "pointer", textAlign: "left", fontWeight: active === id ? 600 : 400, transition: "all var(--t-fast) var(--ease)" }}>
              <Icon size={16} />
              <span>{label}</span>
            </button>
          ))}
        </aside>

        <section style={{ background: "var(--s2)", border: "1px solid var(--b1)", borderRadius: "var(--r-lg)", boxShadow: "var(--el-1)", padding: 18, minWidth: 0 }}>
          {message && <Banner>{message}</Banner>}
          {error && <Banner tone="error">{error}</Banner>}
          {!error && loadError && <Banner tone="error">{loadError}</Banner>}

          {loading && (
            <div style={{ color: "var(--t3)", fontSize: 13 }}>Loading account settings...</div>
          )}

          {!loading && active === "profile" && profile && (
            <div style={{ display: "grid", gap: 16, maxWidth: 760 }}>
              <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
                <Avatar src={avatar} name={profile.username} />
                <div>
                  <div style={{ color: "var(--t1)", fontWeight: 800 }}>Profile identity</div>
                  <div style={{ color: "var(--t3)", fontSize: 13 }}>Username is shown in the dashboard. Email is stored only in account settings.</div>
                  <input type="file" accept="image/png,image/jpeg,image/webp" onChange={(e) => uploadAvatar(e.target.files?.[0])} style={{ marginTop: 10, color: "var(--t3)" }} />
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10 }}>
                <ProfileStat label="Role" value={profile.role || "viewer"} />
                <ProfileStat label="MFA" value={profile.mfa_enabled ? "Enabled" : "Disabled"} />
                <ProfileStat label="Last login" value={fmtAccountTs(profile.last_login_at)} />
                <ProfileStat label="Source IP" value={profile.last_login_ip || "-"} />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
                <Field label="Username"><Input value={profile.username || ""} onChange={(e) => setProfile({ ...profile, username: e.target.value })} /></Field>
                <Field label="Display name"><Input value={profile.display_name || ""} onChange={(e) => setProfile({ ...profile, display_name: e.target.value })} /></Field>
                <Field label="Email"><Input value={email || ""} disabled /></Field>
                <Field label="Role"><Input value={profile.role || "viewer"} disabled /></Field>
              </div>
              <Button variant="primary" disabled={busy} onClick={saveProfile} style={{ justifySelf: "start" }}>Save profile</Button>
            </div>
          )}

          {!loading && active === "security" && (
            <div style={{ display: "grid", gap: 18, maxWidth: 760 }}>
              <div>
                <div style={{ color: "var(--t1)", fontWeight: 800 }}>Local account security</div>
                <div style={{ color: "var(--t3)", fontSize: 13, marginTop: 4 }}>Password and authenticator-app MFA are handled locally.</div>
              </div>

              <div style={{ background: "var(--s1)", border: "1px solid var(--b1)", borderRadius: "var(--r-md)", padding: 14, display: "grid", gap: 12 }}>
                <div style={{ color: "var(--t1)", fontWeight: 700 }}>Change password</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
                  <Field label="Current password"><Input type="password" value={passwordForm.current_password} onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })} /></Field>
                  <Field label="New password"><Input type="password" value={passwordForm.new_password} onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })} /></Field>
                  {mfaStatus?.mfa_enabled && <Field label="Authenticator code"><Input value={passwordForm.code} onChange={(e) => setPasswordForm({ ...passwordForm, code: e.target.value.replace(/\D/g, "").slice(0, 6) })} /></Field>}
                </div>
                <Button variant="secondary" disabled={busy || !passwordForm.current_password || passwordForm.new_password.length < 10} onClick={changePasswordAction} style={{ justifySelf: "start" }}>Change password</Button>
              </div>

              <div style={{ background: "var(--s1)", border: "1px solid var(--b1)", borderRadius: "var(--r-md)", padding: 14, display: "grid", gap: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
                  <div>
                    <div style={{ color: "var(--t1)", fontWeight: 700 }}>Authenticator app MFA</div>
                    <div style={{ color: "var(--t3)", fontSize: 13, marginTop: 3 }}>
                      Status: {mfaStatus?.mfa_enabled ? "Enabled" : "Disabled"} | Daily check: {mfaStatus?.daily_required ? "Enabled" : "Disabled"}
                    </div>
                  </div>
                  {!mfaStatus?.mfa_enabled && <Button variant="primary" disabled={busy} onClick={startMfaSetup}>Enable MFA</Button>}
                </div>

                {mfaSetup && (
                  <div style={{ display: "grid", gridTemplateColumns: "160px minmax(0, 1fr)", gap: 16, alignItems: "center" }}>
                    <img src={mfaSetup.qr_code_data_url} alt="Authenticator QR code" style={{ width: 150, height: 150, borderRadius: 8, background: "white", padding: 8 }} />
                    <div style={{ display: "grid", gap: 10, minWidth: 0 }}>
                      <div style={{ color: "var(--t2)", fontSize: 13 }}>Manual key</div>
                      <code style={{ color: "var(--t1)", overflowWrap: "anywhere", background: "rgba(0,0,0,0.22)", padding: 8, borderRadius: 6 }}>{mfaSetup.manual_key}</code>
                      <Field label="6-digit code"><Input value={mfaCode} onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" /></Field>
                      <Button variant="primary" disabled={busy || mfaCode.length < 6} onClick={confirmMfaSetup} style={{ justifySelf: "start" }}>Confirm MFA</Button>
                    </div>
                  </div>
                )}

                {mfaStatus?.mfa_enabled && (
                  <div style={{ display: "grid", gap: 10 }}>
                    <div style={{ color: "var(--t2)", fontSize: 13 }}>Disable MFA requires your current password and authenticator code.</div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
                      <Field label="Current password"><Input type="password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} /></Field>
                      <Field label="Authenticator code"><Input value={disableCode} onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, "").slice(0, 6))} /></Field>
                    </div>
                    <Button variant="danger" disabled={busy || !disablePassword || disableCode.length < 6} onClick={disableMfaAction} style={{ justifySelf: "start" }}>Disable MFA</Button>
                  </div>
                )}
              </div>
            </div>
          )}

          {!loading && active === "notifications" && prefs && (
            <PreferenceSection prefs={prefs} setPrefs={setPrefs} keys={[
              ["email_notifications_enabled", "Email notifications"],
              ["incident_notifications_enabled", "Incident notifications"],
              ["alert_notifications_enabled", "Alert notifications"],
              ["weekly_report_enabled", "Weekly report"],
            ]} onSave={savePrefs} busy={busy} />
          )}

          {!loading && active === "preferences" && prefs && (
            <div style={{ display: "grid", gap: 14, maxWidth: 640 }}>
              <Field label="Theme"><Input value={prefs.theme || "system"} onChange={(e) => setPrefs({ ...prefs, theme: e.target.value })} /></Field>
              <Field label="Table density"><Input value={prefs.table_density || "comfortable"} onChange={(e) => setPrefs({ ...prefs, table_density: e.target.value })} /></Field>
              <Field label="Default investigation time range"><Input value={prefs.default_time_range || "Last 24h"} onChange={(e) => setPrefs({ ...prefs, default_time_range: e.target.value })} /></Field>
              <Field label="Default page size"><Input type="number" value={prefs.default_page_size || 100} onChange={(e) => setPrefs({ ...prefs, default_page_size: Number(e.target.value) })} /></Field>
              <Button variant="primary" disabled={busy} onClick={savePrefs} style={{ justifySelf: "start" }}>Save preferences</Button>
            </div>
          )}
        </section>
      </div>
    </>
  );
}

function Avatar({ src, name }) {
  const initials = (name || "?").slice(0, 2).toUpperCase();
  return src ? <img src={src} alt="" style={{ width: 64, height: 64, borderRadius: "50%", objectFit: "cover", border: "1px solid var(--b1)" }} /> : (
    <div style={{ width: 64, height: 64, borderRadius: "50%", display: "grid", placeItems: "center", background: "rgba(37,99,235,0.22)", color: "var(--ac-h)", border: "1px solid rgba(37,99,235,0.35)", fontWeight: 800 }}>{initials}</div>
  );
}

function ProfileStat({ label, value }) {
  return (
    <div style={{ background: "var(--s1)", border: "1px solid var(--b1)", borderRadius: "var(--r-md)", padding: 12 }}>
      <div style={{ fontSize: 11, color: "var(--t3)", textTransform: "uppercase", letterSpacing: "0.07em" }}>{label}</div>
      <div style={{ color: "var(--t1)", fontWeight: 700, marginTop: 5 }}>{value}</div>
    </div>
  );
}

function fmtAccountTs(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toISOString().replace("T", " ").slice(0, 16);
}

function Banner({ tone = "info", children }) {
  const error = tone === "error";
  return <div style={{ marginBottom: 14, padding: "9px 14px", borderRadius: "var(--r-md)", border: `1px solid ${error ? "rgba(207,74,74,0.28)" : "rgba(46,143,74,0.28)"}`, color: error ? "var(--crit)" : "var(--low)", background: error ? "var(--crit-d)" : "var(--low-d)", fontSize: 12 }}>{children}</div>;
}

function Field({ label, children }) {
  return <label style={{ display: "grid", gap: 6 }}><span style={{ fontSize: 11, color: "var(--t3)", textTransform: "uppercase", letterSpacing: "0.07em" }}>{label}</span>{children}</label>;
}

function PreferenceSection({ prefs, setPrefs, keys, onSave, busy }) {
  return (
    <div style={{ display: "grid", gap: 12, maxWidth: 620 }}>
      {keys.map(([key, label]) => (
        <label key={key} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, padding: "10px 0", borderBottom: "1px solid var(--b0)", color: "var(--t2)" }}>
          <span>{label}</span>
          <input type="checkbox" checked={!!prefs[key]} onChange={(e) => setPrefs({ ...prefs, [key]: e.target.checked })} />
        </label>
      ))}
      <Button variant="primary" disabled={busy} onClick={onSave} style={{ justifySelf: "start" }}>Save notifications</Button>
    </div>
  );
}

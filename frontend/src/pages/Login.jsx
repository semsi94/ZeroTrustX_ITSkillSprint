import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";

// ── Styles ────────────────────────────────────────────────────────────
const labelStyle = {
  display: "block",
  fontSize: 10,
  fontWeight: 700,
  color: "var(--t3)",
  textTransform: "uppercase",
  letterSpacing: "0.10em",
  marginBottom: 6,
};

const inputBase = {
  width: "100%",
  boxSizing: "border-box",
  padding: "8px 11px",
  background: "var(--s1)",
  border: "1px solid var(--b1)",
  borderRadius: "var(--r-md)",
  color: "var(--t1)",
  fontSize: 13,
  fontFamily: "var(--font-sans)",
  outline: "none",
  boxShadow: "none",
  transition: "border-color var(--t-fast) var(--ease), box-shadow var(--t-fast) var(--ease)",
};

function focusInput(el) {
  el.style.borderColor = "var(--b3)";
  el.style.boxShadow = "0 0 0 3px var(--ac-r)";
}
function blurInput(el) {
  el.style.borderColor = "var(--b1)";
  el.style.boxShadow = "none";
}

// ── Loading dots ──────────────────────────────────────────────────────
function LoadingDots() {
  return (
    <span style={{ display: "inline-flex", gap: 4, alignItems: "center" }}>
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          style={{
            width: 4, height: 4, borderRadius: "50%",
            background: "rgba(255,255,255,0.70)",
            animation: "pendingBlink 1.2s ease-in-out infinite",
            animationDelay: `${i * 0.18}s`,
            display: "inline-block",
          }}
        />
      ))}
    </span>
  );
}

// ── Primary submit button ─────────────────────────────────────────────
function PrimaryButton({ children, disabled, onClick, type = "button" }) {
  const [pressed, setPressed] = useState(false);

  return (
    <button
      type={type}
      disabled={disabled}
      onClick={(e) => { if (!disabled) onClick?.(e); }}
      onMouseDown={() => setPressed(true)}
      onMouseUp={() => setPressed(false)}
      onMouseLeave={() => setPressed(false)}
      style={{
        marginTop: 4,
        padding: "9px 20px",
        borderRadius: "var(--r-md)",
        fontSize: 13,
        fontWeight: 600,
        fontFamily: "var(--font-sans)",
        cursor: disabled ? "not-allowed" : "pointer",
        background: pressed ? "var(--ac-h)" : "var(--ac)",
        border: "1px solid rgba(61,126,245,0.40)",
        color: "white",
        width: "100%",
        opacity: disabled ? 0.45 : 1,
        boxShadow: pressed ? "inset 0 1px 3px rgba(0,0,0,0.30)" : "var(--el-1)",
        transition: "background var(--t-fast) var(--ease), box-shadow var(--t-fast) var(--ease), opacity var(--t-fast) var(--ease)",
        userSelect: "none",
        letterSpacing: "0.01em",
      }}
      onMouseEnter={(e) => {
        if (!disabled) e.currentTarget.style.background = "var(--ac-h)";
      }}
    >
      {children}
    </button>
  );
}

// ── Ghost button ──────────────────────────────────────────────────────
function GhostButton({ children, onClick, type = "button", disabled }) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      style={{
        marginTop: 2,
        padding: "8px 16px",
        borderRadius: "var(--r-md)",
        fontSize: 12,
        fontWeight: 500,
        fontFamily: "var(--font-sans)",
        cursor: disabled ? "not-allowed" : "pointer",
        background: "transparent",
        border: "1px solid var(--b1)",
        color: "var(--t2)",
        width: "100%",
        transition: "border-color var(--t-fast) var(--ease), background var(--t-fast) var(--ease)",
      }}
      onMouseEnter={(e) => {
        if (!disabled) {
          e.currentTarget.style.background = "var(--s3)";
          e.currentTarget.style.borderColor = "var(--b2)";
        }
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "transparent";
        e.currentTarget.style.borderColor = "var(--b1)";
      }}
    >
      {children}
    </button>
  );
}

// ── Main page ──────────────────────────────────────────────────────────
export default function Login() {
  const { login, verifyMfa } = useAuth();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [code, setCode] = useState("");
  const [rememberDevice, setRememberDevice] = useState(true);
  const [challenge, setChallenge] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    document.title = "Sign in — ZeroTrustX";
  }, []);

  async function submitLogin(e) {
    e.preventDefault();
    if (!identifier.trim() || !password) return;
    setBusy(true);
    setError("");
    try {
      const data = await login(identifier, password);
      if (data?.mfa_required) {
        setChallenge(data);
        setCode("");
        return;
      }
      window.location.href = "/";
    } catch (err) {
      setError(
        err?.response?.data?.error ||
        err?.response?.data?.message ||
        "Unable to sign in"
      );
    } finally {
      setBusy(false);
    }
  }

  async function submitMfa(e) {
    e.preventDefault();
    if (code.length < 6) return;
    setBusy(true);
    setError("");
    try {
      const data = await verifyMfa(challenge.challenge_token, code, rememberDevice);
      if (!data?.success) {
        setError(data?.error || "Invalid or expired verification code");
        return;
      }
      window.location.href = "/";
    } catch (err) {
      setError(
        err?.response?.data?.error ||
        "Invalid or expired verification code"
      );
    } finally {
      setBusy(false);
    }
  }

  const isMfa = !!challenge;

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "var(--s0)",
      padding: 24,
    }}>
      <div
        className="page-in"
        style={{
          width: "100%",
          maxWidth: 364,
          background: "var(--s2)",
          border: "1px solid var(--b2)",
          borderRadius: "var(--r-lg)",
          boxShadow: "var(--el-modal)",
          padding: "36px 32px",
        }}
      >
        {/* Brand */}
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          marginBottom: 28,
          gap: 12,
        }}>
          {/* Logo */}
          <div style={{
            width: 48, height: 48,
            borderRadius: "var(--r-lg)",
            background: "var(--ac)",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 4px 12px rgba(0,0,0,0.40)",
          }}>
            <svg width="22" height="22" viewBox="0 0 24 24"
              fill="none" stroke="white" strokeWidth="2.2"
              strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" />
              <line x1="8" y1="12" x2="16" y2="12" />
            </svg>
          </div>

          <div style={{ textAlign: "center" }}>
            <div style={{
              fontSize: 18,
              fontWeight: 700,
              color: "var(--t1)",
              letterSpacing: "-0.02em",
            }}>
              ZeroTrustX
            </div>
            <div style={{
              fontSize: 9,
              color: "var(--t3)",
              marginTop: 3,
              textTransform: "uppercase",
              letterSpacing: "0.14em",
              fontWeight: 700,
            }}>
              Security Operations Center
            </div>
          </div>
        </div>

        {/* Form */}
        <form
          onSubmit={isMfa ? submitMfa : submitLogin}
          style={{ display: "flex", flexDirection: "column", gap: 14 }}
        >
          {isMfa && (
            <div style={{
              fontSize: 12, color: "var(--t2)",
              textAlign: "center", lineHeight: 1.6, marginBottom: 2,
            }}>
              Enter the 6-digit code from your authenticator app.
            </div>
          )}

          {!isMfa && (
            <>
              {/* Username */}
              <div>
                <label style={labelStyle}>Username or email</label>
                <div style={{ position: "relative" }}>
                  <svg width="13" height="13" viewBox="0 0 24 24"
                    fill="none" stroke="var(--t3)" strokeWidth="2"
                    strokeLinecap="round" strokeLinejoin="round"
                    style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }}>
                    <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" />
                    <circle cx="12" cy="7" r="4" />
                  </svg>
                  <input
                    type="text"
                    value={identifier}
                    onChange={(e) => { setIdentifier(e.target.value); setError(""); }}
                    placeholder="admin"
                    autoComplete="username"
                    required
                    style={{ ...inputBase, paddingLeft: 32 }}
                    onFocus={(e) => focusInput(e.target)}
                    onBlur={(e) => blurInput(e.target)}
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label style={labelStyle}>Password</label>
                <div style={{ position: "relative" }}>
                  <svg width="13" height="13" viewBox="0 0 24 24"
                    fill="none" stroke="var(--t3)" strokeWidth="2"
                    strokeLinecap="round" strokeLinejoin="round"
                    style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }}>
                    <rect x="3" y="11" width="18" height="11" rx="2" />
                    <path d="M7 11V7a5 5 0 0110 0v4" />
                  </svg>
                  <input
                    type={showPass ? "text" : "password"}
                    value={password}
                    onChange={(e) => { setPassword(e.target.value); setError(""); }}
                    placeholder="••••••••••"
                    autoComplete="current-password"
                    required
                    style={{ ...inputBase, paddingLeft: 32, paddingRight: 38 }}
                    onFocus={(e) => focusInput(e.target)}
                    onBlur={(e) => blurInput(e.target)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPass((s) => !s)}
                    title={showPass ? "Hide password" : "Show password"}
                    style={{
                      position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)",
                      width: 24, height: 24,
                      background: "none", border: "none",
                      cursor: "pointer", padding: 0,
                      color: "var(--t3)",
                      display: "flex", alignItems: "center", justifyContent: "center",
                      borderRadius: "var(--r-sm)",
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.color = "var(--t2)"; }}
                    onMouseLeave={(e) => { e.currentTarget.style.color = "var(--t3)"; }}
                  >
                    {showPass ? (
                      <svg width="13" height="13" viewBox="0 0 24 24"
                        fill="none" stroke="currentColor" strokeWidth="2"
                        strokeLinecap="round" strokeLinejoin="round">
                        <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" />
                        <line x1="1" y1="1" x2="23" y2="23" />
                      </svg>
                    ) : (
                      <svg width="13" height="13" viewBox="0 0 24 24"
                        fill="none" stroke="currentColor" strokeWidth="2"
                        strokeLinecap="round" strokeLinejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                    )}
                  </button>
                </div>
              </div>
            </>
          )}

          {isMfa && (
            <>
              <div>
                <label style={labelStyle}>Authenticator code</label>
                <input
                  type="text"
                  value={code}
                  onChange={(e) => {
                    setCode(e.target.value.replace(/\D/g, "").slice(0, 6));
                    setError("");
                  }}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  required
                  style={{
                    ...inputBase,
                    fontFamily: "var(--font-mono)",
                    letterSpacing: "0.4em",
                    textAlign: "center",
                    fontSize: 18,
                  }}
                  onFocus={(e) => focusInput(e.target)}
                  onBlur={(e) => blurInput(e.target)}
                />
              </div>

              <label style={{
                display: "flex", alignItems: "center", gap: 8,
                color: "var(--t2)", fontSize: 12, cursor: "pointer", userSelect: "none",
              }}>
                <input
                  type="checkbox"
                  checked={rememberDevice}
                  onChange={(e) => setRememberDevice(e.target.checked)}
                />
                Trust this device after MFA
              </label>
            </>
          )}

          {/* Error banner */}
          {error && (
            <div style={{
              padding: "8px 12px",
              background: "var(--crit-d)",
              border: "1px solid rgba(207,74,74,0.28)",
              borderRadius: "var(--r-md)",
              fontSize: 12,
              color: "var(--crit)",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}>
              <svg width="12" height="12" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" strokeWidth="2.5"
                strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              {error}
            </div>
          )}

          <PrimaryButton
            type="submit"
            disabled={
              busy ||
              (isMfa ? code.length < 6 : !identifier.trim() || !password)
            }
            onClick={() => {}}
          >
            {busy ? (
              <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                <LoadingDots />
                {isMfa ? "Verifying…" : "Signing in…"}
              </span>
            ) : (
              isMfa ? "Verify" : "Sign In"
            )}
          </PrimaryButton>

          {isMfa && (
            <GhostButton
              type="button"
              disabled={busy}
              onClick={() => { setChallenge(null); setCode(""); setError(""); }}
            >
              Back to login
            </GhostButton>
          )}
        </form>

        {/* Footer */}
        <div style={{
          marginTop: 24,
          paddingTop: 14,
          borderTop: "1px solid var(--b0)",
          textAlign: "center",
        }}>
          <div style={{
            fontSize: 10,
            color: "var(--t4)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 6,
          }}>
            <span style={{
              width: 5, height: 5, borderRadius: "50%",
              background: "var(--low)",
            }} className="tac-pulse" />
            Secure connection · ZeroTrustX SOC
          </div>
        </div>
      </div>
    </div>
  );
}

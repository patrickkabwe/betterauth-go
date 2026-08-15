import { type FormEvent, useMemo, useState } from "react";
import { authClient } from "../lib/auth-client";
import "./AuthCard.css";

function ApexBrand() {
  return (
    <div className="apex-brand">
      <span className="apex-logo" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M13 2 4.5 13.5H11l-1 8.5L19.5 10H13l1-8z" fill="#fff" />
        </svg>
      </span>
      <span className="apex-name">Apex</span>
    </div>
  );
}

function goToSignIn() {
  window.location.assign("/");
}

/**
 * ResetPassword renders at /reset-password. The Go server's
 * GET /reset-password/{token} callback redirects here with ?token=… (or
 * ?error=… when the link is invalid/expired).
 */
export default function ResetPassword() {
  const { token, urlError } = useMemo(() => {
    const params = new URLSearchParams(window.location.search);
    return { token: params.get("token") ?? "", urlError: params.get("error") };
  }, []);

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const invalidLink = !!urlError || !token;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    setBusy(true);
    const { error } = await authClient.resetPassword({ newPassword: password, token });
    setBusy(false);
    if (error) {
      setError(error.message ?? "Could not reset your password. The link may have expired.");
      return;
    }
    setDone(true);
  }

  return (
    <div className="apex-root">
      <div className="apex-shell">
        <ApexBrand />

        <div className="apex-card">
          {invalidLink ? (
            <>
              <h1 className="apex-title">Link expired</h1>
              <p className="apex-subtitle">
                This password reset link is invalid or has expired. Request a new one from the sign-in screen.
              </p>
              <button type="button" className="apex-submit" onClick={goToSignIn}>
                Back to sign in
              </button>
            </>
          ) : done ? (
            <>
              <h1 className="apex-title">Password updated</h1>
              <p className="apex-subtitle">You can now sign in with your new password.</p>
              <button type="button" className="apex-submit" onClick={goToSignIn}>
                Continue to sign in
              </button>
            </>
          ) : (
            <form onSubmit={handleSubmit}>
              <h1 className="apex-title">Set a new password</h1>
              <p className="apex-subtitle">Choose a strong password for your account.</p>

              <div className="apex-field">
                <label htmlFor="apex-new-password">New password</label>
                <input
                  id="apex-new-password"
                  type="password"
                  placeholder="At least 8 characters"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              <div className="apex-field">
                <label htmlFor="apex-confirm-password">Confirm password</label>
                <input
                  id="apex-confirm-password"
                  type="password"
                  placeholder="Re-enter your password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                />
              </div>

              {error && <p className="apex-alert apex-alert-error">{error}</p>}

              <button type="submit" className="apex-submit" disabled={busy}>
                {busy ? "Updating…" : "Reset password"}
              </button>

              <p className="apex-foot">
                Remembered it?{" "}
                <button type="button" className="apex-link" onClick={goToSignIn}>
                  Back to sign in
                </button>
              </p>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

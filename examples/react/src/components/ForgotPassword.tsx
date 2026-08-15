import { type FormEvent, useState } from "react";
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
 * ForgotPassword renders at /forgot-password. The user enters their email and we
 * request a reset link via authClient.requestPasswordReset. The link the server
 * sends points back at /reset-password?token=… (see ResetPassword).
 */
export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const { error } = await authClient.requestPasswordReset({
      email,
      redirectTo: `${window.location.origin}/reset-password`,
    });
    setBusy(false);
    if (error) {
      setError(error.message ?? "Could not send the reset link. Please try again.");
      return;
    }
    setSent(true);
  }

  return (
    <div className="apex-root">
      <div className="apex-shell">
        <ApexBrand />

        <div className="apex-card">
          {sent ? (
            <>
              <h1 className="apex-title">Check your email</h1>
              <p className="apex-subtitle">
                If an account exists for <strong>{email}</strong>, a password reset link is on its way.
              </p>
              <p className="apex-hint">
                Running the example locally? The link is printed in the Go server terminal
                (look for <code>[reset-password]</code>).
              </p>
              <button type="button" className="apex-submit" onClick={goToSignIn}>
                Back to sign in
              </button>
            </>
          ) : (
            <form onSubmit={handleSubmit}>
              <h1 className="apex-title">Forgot password?</h1>
              <p className="apex-subtitle">Enter your email and we&apos;ll send you a reset link.</p>

              <div className="apex-field">
                <label htmlFor="apex-forgot-email">Email</label>
                <input
                  id="apex-forgot-email"
                  type="email"
                  placeholder="name@example.com"
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  autoFocus
                />
              </div>

              {error && <p className="apex-alert apex-alert-error">{error}</p>}

              <button type="submit" className="apex-submit" disabled={busy}>
                {busy ? "Sending…" : "Send reset link"}
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

import { type FormEvent, useState } from "react";
import { authClient } from "../lib/auth-client";
import "./AuthCard.css";

type Mode = "sign-in" | "sign-up";

const COPY = {
  "sign-in": { title: "Welcome back", subtitle: "Sign in to your account", cta: "Sign in" },
  "sign-up": { title: "Create your account", subtitle: "Sign up to get started", cta: "Create account" },
} as const;

function GoogleIcon() {
  return (
    <svg viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.6l6.8-6.8C35.9 2.4 30.4 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.4 13.2 17.7 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.1 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.4c-.5 2.9-2.1 5.3-4.6 7l7.1 5.5c4.2-3.9 6.6-9.6 6.6-17z" />
      <path fill="#FBBC05" d="M10.5 28.3c-.5-1.4-.8-2.9-.8-4.3s.3-3 .8-4.3l-7.9-6.1C1 16.9 0 20.3 0 24s1 7.1 2.6 10.4l7.9-6.1z" />
      <path fill="#34A853" d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.1-5.5c-2 1.3-4.5 2.1-8.8 2.1-6.3 0-11.6-3.7-13.5-9.1l-7.9 6.1C6.5 42.6 14.6 48 24 48z" />
    </svg>
  );
}

function GitHubIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0C3.6 0 0 3.6 0 8c0 3.5 2.3 6.5 5.5 7.6.4.1.5-.2.5-.4v-1.4c-2.2.5-2.7-1-2.7-1-.4-.9-.9-1.2-.9-1.2-.7-.5.1-.5.1-.5.8.1 1.2.8 1.2.8.7 1.2 1.9.9 2.3.7.1-.5.3-.9.5-1.1-1.8-.2-3.6-.9-3.6-4 0-.9.3-1.6.8-2.1-.1-.2-.4-1 .1-2.1 0 0 .7-.2 2.2.8.6-.2 1.3-.3 2-.3s1.4.1 2 .3c1.5-1 2.2-.8 2.2-.8.5 1.1.2 1.9.1 2.1.5.5.8 1.2.8 2.1 0 3.1-1.8 3.7-3.6 4 .3.3.6.8.6 1.5v2.2c0 .2.1.5.5.4C13.7 14.5 16 11.5 16 8c0-4.4-3.6-8-8-8z" />
    </svg>
  );
}

export default function AuthCard({
  onSuccess,
  onShowPlayground,
}: {
  onSuccess?: () => void;
  onShowPlayground?: () => void;
}) {
  const [mode, setMode] = useState<Mode>("sign-in");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const copy = COPY[mode];

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { error } =
      mode === "sign-up"
        ? await authClient.signUp.email({ name, email, password, callbackURL: window.location.origin })
        : await authClient.signIn.email({ email, password, rememberMe: remember });
    setBusy(false);
    if (error) {
      setError(error.message ?? "Something went wrong. Please try again.");
      return;
    }
    onSuccess?.();
  }

  async function social(provider: "google" | "github") {
    setError(null);
    // The client redirects the browser to the provider on success.
    const { error } = await authClient.signIn.social({
      provider,
      callbackURL: window.location.origin,
    });
    if (error) {
      setError(
        error.message ??
          `${provider} sign-in isn't configured. Set ${provider.toUpperCase()}_CLIENT_ID / _SECRET on the server.`,
      );
    }
  }

  return (
    <div className="apex-root">
      <div className="apex-shell">
        <div className="apex-brand">
          <span className="apex-logo" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none">
              <path d="M13 2 4.5 13.5H11l-1 8.5L19.5 10H13l1-8z" fill="#fff" />
            </svg>
          </span>
          <span className="apex-name">Apex</span>
        </div>

        <form className="apex-card" onSubmit={handleSubmit}>
          <h1 className="apex-title">{copy.title}</h1>
          <p className="apex-subtitle">{copy.subtitle}</p>

          {mode === "sign-up" && (
            <div className="apex-field">
              <label htmlFor="apex-name">Name</label>
              <input
                id="apex-name"
                type="text"
                placeholder="Jane Doe"
                autoComplete="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
          )}

          <div className="apex-field">
            <label htmlFor="apex-email">Email</label>
            <input
              id="apex-email"
              type="email"
              placeholder="name@example.com"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div className="apex-field">
            <label htmlFor="apex-password">Password</label>
            <input
              id="apex-password"
              type="password"
              placeholder="Enter your password"
              autoComplete={mode === "sign-up" ? "new-password" : "current-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {mode === "sign-in" && (
            <div className="apex-row">
              <label className="apex-check">
                <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
                <span>Remember me</span>
              </label>
              <button
                type="button"
                className="apex-link"
                onClick={() => window.location.assign("/forgot-password")}
              >
                Forgot password?
              </button>
            </div>
          )}

          {error && <p className="apex-alert apex-alert-error">{error}</p>}

          <button type="submit" className="apex-submit" disabled={busy}>
            {busy ? "Please wait…" : copy.cta}
          </button>

          <div className="apex-divider"><span>or continue with</span></div>

          <div className="apex-oauth">
            <button type="button" className="apex-oauth-btn" onClick={() => social("google")}>
              <GoogleIcon /> Google
            </button>
            <button type="button" className="apex-oauth-btn" onClick={() => social("github")}>
              <GitHubIcon /> GitHub
            </button>
          </div>

          <p className="apex-foot">
            {mode === "sign-in" ? (
              <>
                Don&apos;t have an account?{" "}
                <button type="button" className="apex-link" onClick={() => { setMode("sign-up"); setError(null); }}>
                  Sign up
                </button>
              </>
            ) : (
              <>
                Already have an account?{" "}
                <button type="button" className="apex-link" onClick={() => { setMode("sign-in"); setError(null); }}>
                  Sign in
                </button>
              </>
            )}
          </p>
        </form>

        {onShowPlayground && (
          <button type="button" className="apex-playground-link" onClick={onShowPlayground}>
            Open the developer playground →
          </button>
        )}
      </div>
    </div>
  );
}

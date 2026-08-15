import { type FormEvent, useCallback, useEffect, useState } from "react";
import { authClient, baseURL, getBearerToken } from "./lib/auth-client";
import { fetchClientSchema, type ClientSchema } from "./lib/client-schema";
import { callbackURL, formatError, runAuthAction } from "./lib/helpers";
import AuthCard from "./components/AuthCard";
import ForgotPassword from "./components/ForgotPassword";
import ResetPassword from "./components/ResetPassword";

type Mode = "sign-in" | "sign-up";

function Message({ text, isError }: { text: string | null; isError?: boolean }) {
  if (!text) return null;
  return <p className={`alert ${isError ? "alert-error" : "alert-ok"}`}>{text}</p>;
}

function Section({
  title,
  description,
  children,
  defaultOpen = false,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details className="section" open={defaultOpen}>
      <summary className="section-summary">
        <span className="section-title">{title}</span>
        {description && <span className="section-desc">{description}</span>}
      </summary>
      <div className="section-body">{children}</div>
    </details>
  );
}

function ActionRow({ children }: { children: React.ReactNode }) {
  return <div className="action-row">{children}</div>;
}

export default function App() {
  const { data: session, isPending, error, refetch } = authClient.useSession();
  const [schema, setSchema] = useState<ClientSchema | null>(null);
  const [showPlayground, setShowPlayground] = useState(false);
  const [mode, setMode] = useState<Mode>("sign-in");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [messageIsError, setMessageIsError] = useState(false);

  // Shared form fields
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [otp, setOtp] = useState("");
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [orgSlug, setOrgSlug] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [totpURI, setTotpURI] = useState<string | null>(null);
  const [sessions, setSessions] = useState<
    Array<{ token: string; expiresAt: Date | string }>
  >([]);
  const [accounts, setAccounts] = useState<Array<{ providerId: string; accountId: string }>>([]);
  const [orgs, setOrgs] = useState<Array<{ id: string; name: string; slug: string }>>([]);

  const notify = useCallback((text: string, isError = false) => {
    setMessage(text);
    setMessageIsError(isError);
  }, []);

  const run = useCallback(
    async (fn: () => Promise<void>) => {
      setBusy(true);
      setMessage(null);
      try {
        await fn();
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  useEffect(() => {
    fetchClientSchema(baseURL).then(setSchema);
  }, [baseURL]);

  useEffect(() => {
    if (session?.user.name) setNewName(session.user.name);
    if (session?.user.email) setEmail(session.user.email);
  }, [session?.user.email, session?.user.name]);

  async function handleEmailAuth(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      if (mode === "sign-up") {
        const ok = await runAuthAction(
          () => authClient.signUp.email({ name, email, password }),
          notify,
          "Account created. You are signed in.",
        );
        if (ok && username) {
          await authClient.updateUser({ username });
        }
        if (!ok) return;
      } else {
        const ok = await runAuthAction(
          () => authClient.signIn.email({ email, password }),
          notify,
          "Signed in successfully.",
        );
        if (!ok) return;
      }
      await refetch();
      setPassword("");
    });
  }

  async function handleSignOut() {
    await run(async () => {
      await authClient.signOut();
      sessionStorage.removeItem("better-auth.bearer-token");
      await refetch();
      notify("Signed out.");
    });
  }

  async function handleSocialSignIn(provider: string) {
    await run(async () => {
      const { data, error: socialError } = await authClient.signIn.social({
        provider,
        callbackURL: callbackURL(),
      });
      if (socialError) {
        notify(formatError(socialError), true);
        return;
      }
      if (data?.url) {
        window.location.href = data.url;
      }
    });
  }

  async function handleUsernameSignIn(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const ok = await runAuthAction(
        () => authClient.signIn.username({ username, password }),
        notify,
        "Signed in with username.",
      );
      if (ok) await refetch();
    });
  }

  async function handleAnonymousSignIn() {
    await run(async () => {
      const ok = await runAuthAction(
        () => authClient.signIn.anonymous(),
        notify,
        "Signed in as anonymous guest.",
      );
      if (ok) await refetch();
    });
  }

  async function handleMagicLink(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      await runAuthAction(
        () =>
          authClient.signIn.magicLink({
            email,
            callbackURL: callbackURL(),
          }),
        notify,
        "Magic link sent — check the Go server terminal for the URL.",
      );
    });
  }

  async function handleSendEmailOTP() {
    await run(async () => {
      await runAuthAction(
        () => authClient.emailOtp.sendVerificationOtp({ email, type: "sign-in" }),
        notify,
        "OTP sent — check the Go server terminal.",
      );
    });
  }

  async function handleEmailOTPSignIn(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const ok = await runAuthAction(
        () => authClient.signIn.emailOtp({ email, otp }),
        notify,
        "Signed in with email OTP.",
      );
      if (ok) await refetch();
    });
  }

  async function handleUpdateUser(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const body: Record<string, string> = {};
      if (newName) body.name = newName;
      if (username) body.username = username;
      const ok = await runAuthAction(
        () => authClient.updateUser(body),
        notify,
        "Profile updated.",
      );
      if (ok) await refetch();
    });
  }

  async function handleChangePassword(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const ok = await runAuthAction(
        () =>
          authClient.changePassword({
            currentPassword,
            newPassword,
            revokeOtherSessions: false,
          }),
        notify,
        "Password changed.",
      );
      if (ok) {
        setCurrentPassword("");
        setNewPassword("");
        await refetch();
      }
    });
  }

  async function handleChangeEmail(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      await runAuthAction(
        () => authClient.changeEmail({ newEmail }),
        notify,
        "Change-email flow started — check the Go server terminal if confirmation is required.",
      );
    });
  }

  async function handleSetPassword(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const ok = await runAuthAction(
        () =>
          (
            authClient as typeof authClient & {
              setPassword: (args: { newPassword: string }) => ReturnType<typeof authClient.changePassword>;
            }
          ).setPassword({ newPassword }),
        notify,
        "Password set for OAuth-only account.",
      );
      if (ok) setNewPassword("");
    });
  }

  async function handleVerifyPassword() {
    await run(async () => {
      await runAuthAction(
        () =>
          (
            authClient as typeof authClient & {
              verifyPassword: (args: { password: string }) => ReturnType<typeof authClient.changePassword>;
            }
          ).verifyPassword({ password }),
        notify,
        "Password verified.",
      );
    });
  }

  async function handleSendVerification() {
    await run(async () => {
      await runAuthAction(
        () =>
          authClient.sendVerificationEmail({
            email: session?.user.email ?? email,
            callbackURL: callbackURL(),
          }),
        notify,
        "Verification email sent — check the Go server terminal.",
      );
    });
  }

  async function handleRequestPasswordReset(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      await runAuthAction(
        () =>
          authClient.requestPasswordReset({
            email,
            redirectTo: callbackURL(),
          }),
        notify,
        "Reset link sent — check the Go server terminal.",
      );
    });
  }

  async function handleDeleteUser() {
    if (!confirm("Delete your account? This cannot be undone.")) return;
    await run(async () => {
      const ok = await runAuthAction(
        () =>
          authClient.deleteUser(
            password ? { password } : { callbackURL: callbackURL() },
          ),
        notify,
        password
          ? "Account deleted."
          : "Delete confirmation sent — check the Go server terminal.",
      );
      if (ok) await refetch();
    });
  }

  async function handleListSessions() {
    await run(async () => {
      const { data, error: listError } = await authClient.listSessions();
      if (listError) {
        notify(formatError(listError), true);
        return;
      }
      const list = data ?? [];
      setSessions(list);
      notify(`Found ${list.length} session(s).`);
    });
  }

  async function handleRevokeOtherSessions() {
    await run(async () => {
      const ok = await runAuthAction(
        () => authClient.revokeOtherSessions(),
        notify,
        "Other sessions revoked.",
      );
      if (ok) await handleListSessions();
    });
  }

  async function handleRevokeAllSessions() {
    await run(async () => {
      const ok = await runAuthAction(
        () => authClient.revokeSessions(),
        notify,
        "All sessions revoked.",
      );
      if (ok) {
        await refetch();
        setSessions([]);
      }
    });
  }

  async function handleListAccounts() {
    await run(async () => {
      const { data, error: listError } = await authClient.listAccounts();
      if (listError) {
        notify(formatError(listError), true);
        return;
      }
      const list = (data ?? []) as Array<{ providerId: string; accountId: string }>;
      setAccounts(list);
      notify(`Found ${list.length} linked account(s).`);
    });
  }

  async function handleLinkSocial(provider: string) {
    await run(async () => {
      const { data, error: linkError } = await authClient.linkSocial({
        provider,
        callbackURL: callbackURL(),
      });
      if (linkError) {
        notify(formatError(linkError), true);
        return;
      }
      if (data?.url) window.location.href = data.url;
    });
  }

  async function handleUnlinkAccount(providerId: string) {
    await run(async () => {
      const ok = await runAuthAction(
        () => authClient.unlinkAccount({ providerId }),
        notify,
        `Unlinked ${providerId}.`,
      );
      if (ok) await handleListAccounts();
    });
  }

  async function handleCreateOrg(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const ok = await runAuthAction(
        () => authClient.organization.create({ name: orgName, slug: orgSlug }),
        notify,
        "Organization created.",
      );
      if (ok) await handleListOrgs();
    });
  }

  async function handleListOrgs() {
    await run(async () => {
      const { data, error: listError } = await authClient.organization.list();
      if (listError) {
        notify(formatError(listError), true);
        return;
      }
      const list = (data ?? []) as Array<{ id: string; name: string; slug: string }>;
      setOrgs(list);
      notify(`Found ${list.length} organization(s).`);
    });
  }

  async function handleSetActiveOrg(orgId: string) {
    await run(async () => {
      await runAuthAction(
        () => authClient.organization.setActive({ organizationId: orgId }),
        notify,
        "Active organization updated.",
      );
    });
  }

  async function handleInviteMember(e: FormEvent) {
    e.preventDefault();
    const orgId = orgs[0]?.id;
    if (!orgId) {
      notify("Create or list organizations first.", true);
      return;
    }
    await run(async () => {
      await runAuthAction(
        () =>
          authClient.organization.inviteMember({
            email: inviteEmail,
            role: "member",
            organizationId: orgId,
          }),
        notify,
        "Invitation sent.",
      );
    });
  }

  async function handleEnable2FA() {
    await run(async () => {
      const { data, error: enableError } = await authClient.twoFactor.enable({
        password: currentPassword || password,
      });
      if (enableError) {
        notify(formatError(enableError), true);
        return;
      }
      const uri = (data as { totpURI?: string } | undefined)?.totpURI ?? null;
      setTotpURI(uri);
      notify("2FA enabled — scan the TOTP URI (shown below) and verify with a code.");
    });
  }

  async function handleVerify2FA(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const ok = await runAuthAction(
        () => authClient.twoFactor.verifyTotp({ code: totpCode }),
        notify,
        "2FA verified and activated.",
      );
      if (ok) await refetch();
    });
  }

  async function handleDisable2FA() {
    await run(async () => {
      const ok = await runAuthAction(
        () =>
          authClient.twoFactor.disable({
            password: currentPassword || password,
          }),
        notify,
        "2FA disabled.",
      );
      if (ok) {
        setTotpURI(null);
        await refetch();
      }
    });
  }

  async function handleCheckUsername() {
    await run(async () => {
      const { data, error: checkError } = await authClient.isUsernameAvailable({ username });
      if (checkError) {
        notify(formatError(checkError), true);
        return;
      }
      const available = (data as { available?: boolean } | undefined)?.available;
      notify(available ? `"${username}" is available.` : `"${username}" is taken.`, !available);
    });
  }

  const socialProviders = schema?.features.socialProviders ?? [];
  const pluginIds = schema?.plugins.map((p) => p.id) ?? [];
  const bearerToken = getBearerToken();
  const lastLogin =
    "getLastUsedLoginMethod" in authClient
      ? (authClient as { getLastUsedLoginMethod: () => string | null }).getLastUsedLoginMethod()
      : null;

  // Forgot-password screen: dedicated page to request a reset link.
  if (typeof window !== "undefined" && window.location.pathname === "/forgot-password") {
    return <ForgotPassword />;
  }

  // Password-reset screen: the Go server redirects here (?token=… or ?error=…)
  // after the user opens the reset link from their email.
  if (typeof window !== "undefined" && window.location.pathname === "/reset-password") {
    return <ResetPassword />;
  }

  // Signed-out landing: the polished Apex sign-in card. The full developer
  // playground stays one click away.
  if (!session && !isPending && !showPlayground) {
    return <AuthCard onSuccess={() => refetch()} onShowPlayground={() => setShowPlayground(true)} />;
  }

  return (
    <div className="page">
      <header className="hero">
        <p className="eyebrow">betterauth · go + react</p>
        <h1>Auth playground</h1>
        <p className="lede">
          Manual test harness for the Go server at <code>{baseURL}</code>. Email links, OTPs, and
          magic links are printed in the server terminal.
        </p>
      </header>

      {schema && (
        <div className="feature-bar card">
          <div className="feature-chips">
            <span className="chip">email/password</span>
            {socialProviders.map((p) => (
              <span key={p} className="chip chip-oauth">
                oauth: {p}
              </span>
            ))}
            {pluginIds.map((id) => (
              <span key={id} className="chip chip-plugin">
                {id}
              </span>
            ))}
            {schema.features.bearer && <span className="chip">bearer</span>}
          </div>
        </div>
      )}

      <main className="playground">
        <section className="card card-session">
          <div className="card-header">
            <h2>Session</h2>
            <span className={`badge ${session ? "badge-ok" : "badge-muted"}`}>
              {isPending ? "loading" : session ? "authenticated" : "guest"}
            </span>
          </div>

          {error && <p className="alert alert-error">{error.message}</p>}
          <Message text={message} isError={messageIsError} />

          {isPending ? (
            <p className="muted">Checking session…</p>
          ) : session ? (
            <div className="session-panel">
              <div className="avatar" aria-hidden>
                {(session.user.name ?? session.user.email).charAt(0).toUpperCase()}
              </div>
              <dl className="session-details">
                <div>
                  <dt>Name</dt>
                  <dd>{session.user.name}</dd>
                </div>
                <div>
                  <dt>Email</dt>
                  <dd>{session.user.email}</dd>
                </div>
                <div>
                  <dt>User ID</dt>
                  <dd>
                    <code>{session.user.id}</code>
                  </dd>
                </div>
                <div>
                  <dt>Session expires</dt>
                  <dd>{new Date(session.session.expiresAt).toLocaleString()}</dd>
                </div>
                {lastLogin && (
                  <div>
                    <dt>Last login method</dt>
                    <dd>{lastLogin}</dd>
                  </div>
                )}
              </dl>
              <button
                type="button"
                className="button button-secondary"
                onClick={handleSignOut}
                disabled={busy}
              >
                Sign out
              </button>
            </div>
          ) : (
            <p className="muted">No active session. Use any sign-in method below.</p>
          )}

          {bearerToken && (
            <div className="bearer-panel">
              <dt>Bearer token</dt>
              <dd>
                <code className="token-preview">{bearerToken.slice(0, 48)}…</code>
              </dd>
            </div>
          )}
        </section>

        <div className="sections">
          <Section title="Email sign-in / sign-up" description="Core email/password auth" defaultOpen>
            <div className="tabs" role="tablist" aria-label="Auth mode">
              <button
                role="tab"
                type="button"
                aria-selected={mode === "sign-in"}
                className={mode === "sign-in" ? "tab active" : "tab"}
                onClick={() => setMode("sign-in")}
              >
                Sign in
              </button>
              <button
                role="tab"
                type="button"
                aria-selected={mode === "sign-up"}
                className={mode === "sign-up" ? "tab active" : "tab"}
                onClick={() => setMode("sign-up")}
              >
                Sign up
              </button>
            </div>
            <form className="form" onSubmit={handleEmailAuth}>
              {mode === "sign-up" && (
                <label className="field">
                  <span>Name</span>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Doe"
                    required
                    autoComplete="name"
                  />
                </label>
              )}
              <label className="field">
                <span>Email</span>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
                  autoComplete="email"
                />
              </label>
              {mode === "sign-up" && (
                <label className="field">
                  <span>Username (optional)</span>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="jane_doe"
                    autoComplete="username"
                  />
                </label>
              )}
              <label className="field">
                <span>Password</span>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  minLength={8}
                  autoComplete={mode === "sign-up" ? "new-password" : "current-password"}
                />
              </label>
              <button className="button button-primary" type="submit" disabled={busy}>
                {busy ? "Working…" : mode === "sign-up" ? "Create account" : "Sign in"}
              </button>
            </form>
          </Section>

          <Section title="OAuth" description="Google & GitHub social sign-in">
            {socialProviders.length === 0 ? (
              <p className="muted">
                No OAuth providers configured. Set <code>GOOGLE_CLIENT_ID</code> /{" "}
                <code>GITHUB_CLIENT_ID</code> (and secrets) on the Go server.
              </p>
            ) : (
              <ActionRow>
                {socialProviders.includes("google") && (
                  <button
                    type="button"
                    className="button button-secondary"
                    disabled={busy}
                    onClick={() => handleSocialSignIn("google")}
                  >
                    Sign in with Google
                  </button>
                )}
                {socialProviders.includes("github") && (
                  <button
                    type="button"
                    className="button button-secondary"
                    disabled={busy}
                    onClick={() => handleSocialSignIn("github")}
                  >
                    Sign in with GitHub
                  </button>
                )}
              </ActionRow>
            )}
          </Section>

          <Section title="Username plugin" description="Sign in with username">
            <form className="form" onSubmit={handleUsernameSignIn}>
              <label className="field">
                <span>Username</span>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="jane_doe"
                  required
                />
              </label>
              <label className="field">
                <span>Password</span>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </label>
              <ActionRow>
                <button className="button button-primary" type="submit" disabled={busy}>
                  Sign in with username
                </button>
                <button
                  type="button"
                  className="button button-secondary"
                  disabled={busy || !username}
                  onClick={handleCheckUsername}
                >
                  Check availability
                </button>
              </ActionRow>
            </form>
          </Section>

          <Section title="Anonymous plugin" description="Guest sessions without credentials">
            <ActionRow>
              <button
                type="button"
                className="button button-secondary"
                disabled={busy}
                onClick={handleAnonymousSignIn}
              >
                Sign in anonymously
              </button>
            </ActionRow>
          </Section>

          <Section title="Magic link plugin" description="Passwordless email link">
            <form className="form" onSubmit={handleMagicLink}>
              <label className="field">
                <span>Email</span>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </label>
              <button className="button button-primary" type="submit" disabled={busy}>
                Send magic link
              </button>
            </form>
          </Section>

          <Section title="Email OTP plugin" description="One-time password via email">
            <form className="form" onSubmit={handleEmailOTPSignIn}>
              <label className="field">
                <span>Email</span>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                <span>OTP (from server terminal)</span>
                <input
                  type="text"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  placeholder="123456"
                  required
                />
              </label>
              <ActionRow>
                <button
                  type="button"
                  className="button button-secondary"
                  disabled={busy}
                  onClick={handleSendEmailOTP}
                >
                  Send OTP
                </button>
                <button className="button button-primary" type="submit" disabled={busy}>
                  Sign in with OTP
                </button>
              </ActionRow>
            </form>
          </Section>

          <Section title="Account management" description="Profile, password, email, delete">
            <form className="form" onSubmit={handleUpdateUser}>
              <label className="field">
                <span>Display name</span>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Jane Doe"
                />
              </label>
              <label className="field">
                <span>Username</span>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="jane_doe"
                />
              </label>
              <button className="button button-secondary" type="submit" disabled={busy || !session}>
                Update profile
              </button>
            </form>

            <form className="form form-divider" onSubmit={handleChangePassword}>
              <h3 className="subheading">Change password</h3>
              <label className="field">
                <span>Current password</span>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </label>
              <label className="field">
                <span>New password</span>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </label>
              <button className="button button-secondary" type="submit" disabled={busy || !session}>
                Change password
              </button>
            </form>

            <form className="form form-divider" onSubmit={handleChangeEmail}>
              <h3 className="subheading">Change email</h3>
              <label className="field">
                <span>New email</span>
                <input
                  type="email"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  required
                />
              </label>
              <button className="button button-secondary" type="submit" disabled={busy || !session}>
                Change email
              </button>
            </form>

            <form className="form form-divider" onSubmit={handleSetPassword}>
              <h3 className="subheading">Set password (OAuth-only users)</h3>
              <label className="field">
                <span>New password</span>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </label>
              <button className="button button-secondary" type="submit" disabled={busy || !session}>
                Set password
              </button>
            </form>

            <div className="form form-divider">
              <h3 className="subheading">Verify password</h3>
              <ActionRow>
                <button
                  type="button"
                  className="button button-secondary"
                  disabled={busy || !session || !password}
                  onClick={handleVerifyPassword}
                >
                  Verify current password field
                </button>
                <button
                  type="button"
                  className="button button-secondary"
                  disabled={busy || !session}
                  onClick={handleSendVerification}
                >
                  Send verification email
                </button>
              </ActionRow>
            </div>

            <form className="form form-divider" onSubmit={handleRequestPasswordReset}>
              <h3 className="subheading">Request password reset</h3>
              <label className="field">
                <span>Email</span>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </label>
              <button className="button button-secondary" type="submit" disabled={busy}>
                Send reset link
              </button>
            </form>

            <div className="form form-divider">
              <h3 className="subheading">Delete account</h3>
              <p className="muted small">
                Enter your password to delete immediately, or leave blank to receive a confirmation
                link in the server terminal.
              </p>
              <ActionRow>
                <button
                  type="button"
                  className="button button-danger"
                  disabled={busy || !session}
                  onClick={handleDeleteUser}
                >
                  Delete account
                </button>
              </ActionRow>
            </div>
          </Section>

          <Section title="Session management" description="List and revoke sessions">
            <ActionRow>
              <button
                type="button"
                className="button button-secondary"
                disabled={busy || !session}
                onClick={handleListSessions}
              >
                List sessions
              </button>
              <button
                type="button"
                className="button button-secondary"
                disabled={busy || !session}
                onClick={handleRevokeOtherSessions}
              >
                Revoke other sessions
              </button>
              <button
                type="button"
                className="button button-danger"
                disabled={busy || !session}
                onClick={handleRevokeAllSessions}
              >
                Revoke all sessions
              </button>
            </ActionRow>
            {sessions.length > 0 && (
              <ul className="list">
                {sessions.map((s) => (
                  <li key={s.token}>
                    <code>{s.token.slice(0, 16)}…</code>
                    <span className="muted">expires {new Date(s.expiresAt).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="Linked accounts" description="OAuth account linking">
            <ActionRow>
              <button
                type="button"
                className="button button-secondary"
                disabled={busy || !session}
                onClick={handleListAccounts}
              >
                List accounts
              </button>
              {socialProviders.includes("github") && (
                <button
                  type="button"
                  className="button button-secondary"
                  disabled={busy || !session}
                  onClick={() => handleLinkSocial("github")}
                >
                  Link GitHub
                </button>
              )}
              {socialProviders.includes("google") && (
                <button
                  type="button"
                  className="button button-secondary"
                  disabled={busy || !session}
                  onClick={() => handleLinkSocial("google")}
                >
                  Link Google
                </button>
              )}
            </ActionRow>
            {accounts.length > 0 && (
              <ul className="list">
                {accounts.map((a) => (
                  <li key={a.accountId}>
                    <strong>{a.providerId}</strong>
                    <button
                      type="button"
                      className="button button-ghost"
                      disabled={busy}
                      onClick={() => handleUnlinkAccount(a.providerId)}
                    >
                      Unlink
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="Organization plugin" description="Teams, members, invitations">
            <form className="form" onSubmit={handleCreateOrg}>
              <label className="field">
                <span>Organization name</span>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="Acme Inc"
                  required
                />
              </label>
              <label className="field">
                <span>Slug</span>
                <input
                  type="text"
                  value={orgSlug}
                  onChange={(e) => setOrgSlug(e.target.value)}
                  placeholder="acme"
                  required
                />
              </label>
              <ActionRow>
                <button className="button button-primary" type="submit" disabled={busy || !session}>
                  Create organization
                </button>
                <button
                  type="button"
                  className="button button-secondary"
                  disabled={busy || !session}
                  onClick={handleListOrgs}
                >
                  List organizations
                </button>
              </ActionRow>
            </form>

            {orgs.length > 0 && (
              <ul className="list">
                {orgs.map((org) => (
                  <li key={org.id}>
                    <span>
                      {org.name} (<code>{org.slug}</code>)
                    </span>
                    <button
                      type="button"
                      className="button button-ghost"
                      disabled={busy}
                      onClick={() => handleSetActiveOrg(org.id)}
                    >
                      Set active
                    </button>
                  </li>
                ))}
              </ul>
            )}

            <form className="form form-divider" onSubmit={handleInviteMember}>
              <h3 className="subheading">Invite member (first org)</h3>
              <label className="field">
                <span>Email</span>
                <input
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="teammate@example.com"
                  required
                />
              </label>
              <button className="button button-secondary" type="submit" disabled={busy || !session}>
                Send invitation
              </button>
            </form>
          </Section>

          <Section title="Two-factor plugin" description="TOTP setup and verification">
            <p className="muted small">
              Uses the password field above (or current-password field in account section) to confirm
              identity when enabling/disabling.
            </p>
            <ActionRow>
              <button
                type="button"
                className="button button-secondary"
                disabled={busy || !session}
                onClick={handleEnable2FA}
              >
                Enable 2FA
              </button>
              <button
                type="button"
                className="button button-danger"
                disabled={busy || !session}
                onClick={handleDisable2FA}
              >
                Disable 2FA
              </button>
            </ActionRow>
            {totpURI && (
              <p className="code-block">
                <code>{totpURI}</code>
              </p>
            )}
            <form className="form" onSubmit={handleVerify2FA}>
              <label className="field">
                <span>TOTP code</span>
                <input
                  type="text"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  placeholder="000000"
                  inputMode="numeric"
                />
              </label>
              <button className="button button-primary" type="submit" disabled={busy || !session}>
                Verify TOTP
              </button>
            </form>
          </Section>
        </div>
      </main>

      <footer className="footer">
        <p>
          Start the Go server: <code>go run ./examples/basic</code> — then{" "}
          <code>cd examples/react && npm run dev</code>
        </p>
      </footer>
    </div>
  );
}

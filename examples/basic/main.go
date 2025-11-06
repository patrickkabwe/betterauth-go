package main

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/store"
	sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"
	"github.com/patrickkabwe/betterauth-go/types"

	_ "modernc.org/sqlite"
)

// newStore returns a SQL-backed store. Defaults to ./better-auth-example.db so
// ExtStore plugins (organization, two-factor, …) work out of the box.
// Set DATABASE_PATH=:memory: for an ephemeral DB or a file path to persist elsewhere.
func newStore() store.Store {
	path := os.Getenv("DATABASE_PATH")
	if path == "" {
		path = "better-auth-example.db"
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)"
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared&_pragma=busy_timeout(5000)"
	}
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	st := sqlstore.New(db, sqlstore.SQLite)
	if err := st.Migrate(context.Background()); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("store: SQLite at %s", path)
	return st
}

func main() {
	deleteUserEnabled := true
	inputAllowed := true

	a, err := auth.New(auth.Config{
		AppName: "Better Auth Go Example",
		Secret:  "change-me-to-a-long-random-secret",
		// OldSecrets enables zero-downtime secret rotation: existing cookies
		// signed with a previous secret keep working.
		OldSecrets: envList("OLD_SECRETS"),
		BaseURL:    "http://localhost:8080",
		// Trusted origins drive both CORS and origin-based CSRF protection.
		// Wildcards are supported, e.g. "https://*.example.com".
		TrustedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:5173",
		},
		Store: newStore(),

		// Rate limiting: 100 req/min per IP by default, with a stricter rule
		// for authentication endpoints.
		RateLimit: auth.RateLimitConfig{
			Enabled: true,
			Window:  time.Minute,
			Max:     100,
			CustomRules: map[string]auth.RateLimitRule{
				"/sign-in/*":     {Window: time.Minute, Max: 10},
				"/sign-up/email": {Window: time.Minute, Max: 5},
			},
		},

		EmailAndPassword: auth.EmailAndPasswordConfig{
			Enabled: true,
			SendResetPassword: func(_ context.Context, data types.ResetPasswordEmailData) error {
				log.Printf("[reset-password] email=%s url=%s token=%s", data.User.Email, data.URL, data.Token)
				return nil
			},
		},
		EmailVerification: auth.EmailVerificationConfig{
			SendVerificationEmail: func(_ context.Context, data types.VerificationEmailData) error {
				log.Printf("[verify-email] email=%s url=%s token=%s", data.User.Email, data.URL, data.Token)
				return nil
			},
		},

		User: auth.UserConfig{
			AdditionalFields: map[string]auth.AdditionalFieldDef{
				constants.FieldUsername: {Type: "string", Input: &inputAllowed},
			},
			ChangeEmail: auth.ChangeEmailConfig{
				Enabled: true,
			},
			DeleteUser: auth.DeleteUserConfig{
				Enabled: &deleteUserEnabled,
				SendDeleteAccountURL: func(_ context.Context, user types.User, url, token string) error {
					log.Printf("[delete-user] email=%s url=%s token=%s", user.Email, url, token)
					return nil
				},
			},
		},

		// Database hooks run around core store operations.
		DatabaseHooks: auth.DatabaseHooksConfig{
			User: &auth.UserDatabaseHooks{
				AfterCreate: func(_ context.Context, u *types.User) error {
					log.Printf("hook: user created %s (%s)", u.ID, u.Email)
					return nil
				},
			},
			Session: &auth.SessionDatabaseHooks{
				AfterCreate: func(_ context.Context, s *types.Session) error {
					log.Printf("hook: session created for user %s from %s", s.UserID, s.IPAddress)
					return nil
				},
			},
		},

		Advanced: auth.AdvancedConfig{
			// In production behind HTTPS, share the session across subdomains
			// and harden cookies:
			//   UseSecureCookies: true,
			//   CrossSubDomainCookies: auth.CrossSubDomainConfig{Enabled: true, Domain: ".example.com"},
			//
			// Trust a proxy's client IP header:
			IPAddressHeaders: []string{"X-Forwarded-For", "X-Real-IP"},
		},

		Google: auth.GoogleProviderConfig{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		},
		GitHub: auth.GitHubProviderConfig{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		},
		Account: auth.AccountConfig{
			AccountLinking: auth.AccountLinkingConfig{
				TrustedProviders: []string{constants.ProviderGoogle, constants.ProviderGitHub},
			},
		},
		Plugins: []auth.Plugin{
			plugins.Bearer(plugins.BearerOptions{}),
			plugins.Username(plugins.UsernameOptions{}),
			plugins.Organization(plugins.OrganizationOptions{}),
			plugins.TwoFactor(plugins.TwoFactorOptions{Issuer: "Better Auth Go Example"}),
			plugins.Anonymous(plugins.AnonymousOptions{}),
			plugins.LastLoginMethod(plugins.LastLoginMethodOptions{StoreInCookie: true}),
			plugins.MagicLink(plugins.MagicLinkOptions{
				SendMagicLink: func(_ context.Context, email, link, token string) error {
					log.Printf("[magic-link] email=%s link=%s token=%s", email, link, token)
					return nil
				},
			}),
			plugins.EmailOTP(plugins.EmailOTPOptions{
				SendOTP: func(_ context.Context, email, otp, typ string) error {
					log.Printf("[email-otp] type=%s email=%s otp=%s", typ, email, otp)
					return nil
				},
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Mount Better Auth handler at /api/auth
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", a.Handler()))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Better Auth Go server running.")
		fmt.Fprintln(w, "Auth endpoints: http://localhost:8080/api/auth/*")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Enabled plugins: bearer, username, organization, two-factor,")
		fmt.Fprintln(w, "  anonymous, last-login-method, magic-link, email-otp")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Email / link flows log URLs and OTPs to this terminal.")
		fmt.Fprintln(w, "OAuth: set GOOGLE_CLIENT_ID/SECRET and/or GITHUB_CLIENT_ID/SECRET.")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Client schema (type inference):")
		fmt.Fprintln(w, "  GET http://localhost:8080/api/auth/client-schema")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "React playground: cd examples/react && npm run dev")
	})

	addr := ":8080"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// envList splits a comma/space-free env var into a single-element slice; empty
// returns nil. Kept simple for the example.
func envList(key string) []string {
	if v := os.Getenv(key); v != "" {
		return []string{v}
	}
	return nil
}

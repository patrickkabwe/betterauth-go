package auth

import (
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"net/http"

	"github.com/patrickkabwe/betterauth-go/store"
)

// Auth is a Better Auth compatible server instance.
type Auth struct {
	cfg    resolved
	routes []route
}

// New creates a new Auth instance.
func New(opts Config) (*Auth, error) {
	if opts.Secret == "" {
		return nil, berrors.ErrSecretRequired
	}
	if opts.Store == nil {
		return nil, berrors.ErrStoreRequired
	}
	cfg := resolveConfig(opts)
	return &Auth{cfg: cfg, routes: mergePluginRoutes(routeTable, cfg.plugins)}, nil
}

// Handler returns an http.Handler that serves all Better Auth endpoints.
// Mount it at the configured BasePath (default /api/auth).
//
// Example with net/http:
//
//	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", auth.Handler()))
//
// Example with chi:
//
//	r.Mount("/api/auth", auth.Handler())
func (a *Auth) Handler() http.Handler {
	return a.handler()
}

// Store returns the configured store.
func (a *Auth) Store() store.Store {
	return a.cfg.store
}

// BasePath returns the configured base path.
func (a *Auth) BasePath() string {
	return a.cfg.basePath
}

// BaseURL returns the configured base URL.
func (a *Auth) BaseURL() string {
	return a.cfg.baseURL
}

// AppName returns the configured application name.
func (a *Auth) AppName() string {
	return a.cfg.appName
}

// Plugins returns configured plugins.
func (a *Auth) Plugins() []Plugin {
	return a.cfg.plugins
}

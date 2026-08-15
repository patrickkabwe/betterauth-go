package auth

import (
	"net/http"
	"sort"

	"github.com/patrickkabwe/betterauth-go/constants"
)

// ClientPluginInfo describes how official TS clients pair with a server plugin.
type ClientPluginInfo struct {
	Package string `json:"package"`
	Import  string `json:"import"`
}

// ClientEndpoint describes one HTTP route exposed to clients.
type ClientEndpoint struct {
	Method string  `json:"method"`
	Path   string  `json:"path"`
	Plugin *string `json:"plugin,omitempty"`
}

// ClientAdditionalField describes a custom user field for inferAdditionalFields.
type ClientAdditionalField struct {
	Type         string `json:"type"`
	Required     bool   `json:"required"`
	Input        bool   `json:"input"`
	DefaultValue any    `json:"defaultValue,omitempty"`
}

// ClientPluginSchema groups endpoints and client pairing for one server plugin.
type ClientPluginSchema struct {
	ID           string            `json:"id"`
	ClientPlugin *ClientPluginInfo `json:"clientPlugin"`
	Endpoints    []ClientEndpoint  `json:"endpoints"`
}

// ClientFeatures summarizes enabled auth features.
type ClientFeatures struct {
	EmailAndPassword bool     `json:"emailAndPassword"`
	SocialProviders  []string `json:"socialProviders"`
	Bearer           bool     `json:"bearer"`
}

// ClientSchema is returned by GET /client-schema for client type inference.
type ClientSchema struct {
	Version  int                              `json:"version"`
	AppName  string                           `json:"appName"`
	BaseURL  string                           `json:"baseURL"`
	BasePath string                           `json:"basePath"`
	Features ClientFeatures                   `json:"features"`
	User     map[string]ClientAdditionalField `json:"user"`
	Plugins  []ClientPluginSchema             `json:"plugins"`
	Routes   []ClientEndpoint                 `json:"routes"`
}

// ClientSchemaPlugin optionally contributes client pairing metadata.
type ClientSchemaPlugin interface {
	Plugin
	ClientPluginInfo() *ClientPluginInfo
}

func handleClientSchema(c *Context) {
	c.WriteJSON(http.StatusOK, c.Auth.buildClientSchema())
}

func (a *Auth) buildClientSchema() ClientSchema {
	pluginRoutes := make(map[string][]ClientEndpoint)
	pluginIDs := make([]string, 0, len(a.cfg.plugins))
	pluginInfo := make(map[string]*ClientPluginInfo)
	serverOnlyRoutes := make(map[string]bool)
	hasBearer := false

	for _, p := range a.cfg.plugins {
		id := p.ID()
		pluginIDs = append(pluginIDs, id)
		if id == constants.PluginBearer {
			hasBearer = true
		}
		if cp, ok := p.(ClientSchemaPlugin); ok {
			if info := cp.ClientPluginInfo(); info != nil {
				pluginInfo[id] = info
			}
		}
		for _, r := range p.Routes() {
			key := r.Method + " " + r.Pattern
			if r.ServerOnly {
				serverOnlyRoutes[key] = true
				continue
			}
			pluginRoutes[id] = append(pluginRoutes[id], ClientEndpoint{
				Method: r.Method,
				Path:   r.Pattern,
				Plugin: strPtr(id),
			})
		}
	}
	sort.Strings(pluginIDs)

	coreRoutes := make([]ClientEndpoint, 0, len(a.routes))
	for _, rt := range a.routes {
		key := rt.method + " " + rt.pattern
		if rt.pattern == "/client-schema" || serverOnlyRoutes[key] {
			continue
		}
		ep := ClientEndpoint{Method: rt.method, Path: rt.pattern}
		for _, pid := range pluginIDs {
			for _, pr := range pluginRoutes[pid] {
				if pr.Method == rt.method && pr.Path == rt.pattern {
					ep.Plugin = strPtr(pid)
					break
				}
			}
			if ep.Plugin != nil {
				break
			}
		}
		coreRoutes = append(coreRoutes, ep)
	}

	plugins := make([]ClientPluginSchema, 0, len(pluginIDs))
	for _, id := range pluginIDs {
		eps := pluginRoutes[id]
		if eps == nil {
			eps = []ClientEndpoint{}
		}
		sort.Slice(eps, func(i, j int) bool {
			if eps[i].Path == eps[j].Path {
				return eps[i].Method < eps[j].Method
			}
			return eps[i].Path < eps[j].Path
		})
		plugins = append(plugins, ClientPluginSchema{
			ID:           id,
			ClientPlugin: pluginInfo[id],
			Endpoints:    eps,
		})
	}

	userFields := make(map[string]ClientAdditionalField, len(a.cfg.user.additionalFields))
	for name, def := range a.cfg.user.additionalFields {
		input := def.allowsInput()
		userFields[name] = ClientAdditionalField{
			Type:         def.Type,
			Required:     def.Required,
			Input:        input,
			DefaultValue: def.DefaultValue,
		}
	}

	social := make([]string, 0, len(a.cfg.socialProviders))
	for id := range a.cfg.socialProviders {
		social = append(social, id)
	}
	sort.Strings(social)

	sort.Slice(coreRoutes, func(i, j int) bool {
		if coreRoutes[i].Path == coreRoutes[j].Path {
			return coreRoutes[i].Method < coreRoutes[j].Method
		}
		return coreRoutes[i].Path < coreRoutes[j].Path
	})

	return ClientSchema{
		Version:  1,
		AppName:  a.cfg.appName,
		BaseURL:  a.cfg.baseURL,
		BasePath: a.cfg.basePath,
		Features: ClientFeatures{
			EmailAndPassword: a.cfg.emailPassword.enabled,
			SocialProviders:  social,
			Bearer:           hasBearer,
		},
		User:    userFields,
		Plugins: plugins,
		Routes:  coreRoutes,
	}
}

// ClientSchemaJSON returns the client schema for tooling and codegen.
func (a *Auth) ClientSchemaJSON() ClientSchema {
	return a.buildClientSchema()
}

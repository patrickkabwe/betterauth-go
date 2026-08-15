package plugins

import "github.com/patrickkabwe/betterauth-go/auth"

func rt(method, pattern string, fn func(*auth.Context)) auth.PluginRoute {
	return auth.PluginRoute{Method: method, Pattern: pattern, Handler: fn}
}

func srt(method, pattern string, fn func(*auth.Context)) auth.PluginRoute {
	return auth.PluginRoute{Method: method, Pattern: pattern, Handler: fn, ServerOnly: true}
}

type basePlugin struct {
	id     string
	routes []auth.PluginRoute
	hooks  *auth.PluginHooks
}

func (b basePlugin) ID() string                 { return b.id }
func (b basePlugin) Routes() []auth.PluginRoute { return b.routes }
func (b basePlugin) Hooks() *auth.PluginHooks   { return b.hooks }

func (b basePlugin) ClientPluginInfo() *auth.ClientPluginInfo {
	return clientPluginInfo(b.id)
}

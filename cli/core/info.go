package core

import (
	"encoding/json"
	"fmt"
	"runtime"
)

// runInfo prints diagnostic information about the Better Auth setup and
// environment. It mirrors `npx @better-auth/cli info`.
func runInfo(args []string, opts Options) error {
	fs := newFlagSet("info", opts)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	version := opts.Version
	if version == "" {
		version = "dev"
	}

	info := map[string]any{
		"betterauth": version,
		"system": map[string]any{
			"go":   runtime.Version(),
			"os":   runtime.GOOS,
			"arch": runtime.GOARCH,
		},
	}

	if a := opts.Auth; a != nil {
		plugins := make([]map[string]any, 0, len(a.Plugins()))
		for _, p := range a.Plugins() {
			plugins = append(plugins, map[string]any{
				"id":     p.ID(),
				"routes": len(p.Routes()),
			})
		}
		info["auth"] = map[string]any{
			"appName":  a.AppName(),
			"baseURL":  a.BaseURL(),
			"basePath": a.BasePath(),
			"store":    fmt.Sprintf("%T", a.Store()),
			"plugins":  plugins,
		}
	}

	if asJSON {
		enc := json.NewEncoder(opts.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	// Human-readable output.
	fmt.Fprintf(opts.Stdout, "betterauth: %s\n", version)
	fmt.Fprintf(opts.Stdout, "system:     %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if a := opts.Auth; a != nil {
		fmt.Fprintln(opts.Stdout, "")
		fmt.Fprintf(opts.Stdout, "app name:   %s\n", a.AppName())
		fmt.Fprintf(opts.Stdout, "base URL:   %s\n", a.BaseURL())
		fmt.Fprintf(opts.Stdout, "base path:  %s\n", a.BasePath())
		fmt.Fprintf(opts.Stdout, "store:      %T\n", a.Store())
		plugins := a.Plugins()
		fmt.Fprintf(opts.Stdout, "plugins:    %d\n", len(plugins))
		for _, p := range plugins {
			fmt.Fprintf(opts.Stdout, "  - %s (%d routes)\n", p.ID(), len(p.Routes()))
		}
	} else {
		fmt.Fprintln(opts.Stdout, "\n(no auth instance supplied; pass Options.Auth for config details)")
	}
	return nil
}

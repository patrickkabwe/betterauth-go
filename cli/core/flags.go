package core

import "flag"

// newFlagSet creates a FlagSet that writes usage/errors to the configured
// stderr and does not call os.Exit on parse errors. Go's flag package accepts
// both -flag and --flag forms, matching the documented CLI options.
func newFlagSet(name string, opts Options) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(opts.Stderr)
	return fs
}

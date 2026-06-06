package auth

func runConfigBeforeHook(c *Context, hooks HooksConfig) bool {
	if hooks.Before == nil {
		return true
	}
	return hooks.Before(c)
}

func runConfigAfterHook(c *Context, hooks HooksConfig) {
	if hooks.After != nil {
		hooks.After(c)
	}
}

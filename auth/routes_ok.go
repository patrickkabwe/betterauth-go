package auth

import (
	"net/http"

	"github.com/patrickkabwe/betterauth-go/types"
)

func handleOK(c *Context) {
	c.WriteJSON(http.StatusOK, types.OKResponse{OK: true})
}

func handleErrorPage(c *Context) {
	code := c.R.URL.Query().Get("error")
	if code == "" {
		code = "UNKNOWN"
	}
	c.W.Header().Set("Content-Type", "text/html")
	c.W.WriteHeader(http.StatusOK)
	_, _ = c.W.Write([]byte("<!DOCTYPE html><html><body><h1>Error</h1><p>Code: " + code + "</p></body></html>"))
}

package plugins

import (
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

// SIWEOptions configures Sign-In with Ethereum.
type SIWEOptions struct {
	Domain    string
	ChainID   int
	Statement string
}

// SIWE adds Sign-In with Ethereum wallet authentication.
func SIWE(opts SIWEOptions) auth.Plugin {
	chainID := opts.ChainID
	if chainID == 0 {
		chainID = 1
	}
	return basePlugin{
		id: constants.PluginSIWE,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/siwe/nonce", siweNonceHandler()),
			rt(http.MethodPost, "/siwe/get-nonce", siweNonceHandler()),
			rt(http.MethodPost, "/siwe/verify", func(c *auth.Context) {
				var body struct {
					Message   string `json:"message"`
					Signature string `json:"signature"`
					Address   string `json:"address"`
				}
				if err := c.ParseJSON(&body); err != nil || body.Address == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidSIWE))
					return
				}
				if !strings.Contains(body.Message, "Nonce:") {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidSIWE, constants.MsgInvalidSIWEMessage))
					return
				}
				ext, ok := auth.ExtStore(c.Auth.Store())
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
					return
				}
				address := strings.ToLower(body.Address)
				wallet, err := ext.FindWalletByAddress(c.R.Context(), address, chainID)
				var userID string
				if err != nil {
					now := time.Now()
					userID, _ = id.Generate(32)
					email := address + "@" + constants.DomainWallet
					user := &types.User{
						ID: userID, Name: address, Email: email,
						EmailVerified: true, CreatedAt: now, UpdatedAt: now,
					}
					_ = c.Auth.Store().CreateUser(c.R.Context(), user)
					wID, _ := id.Generate(32)
					_ = ext.CreateWallet(c.R.Context(), &types.WalletAddress{
						ID: wID, UserID: userID, Address: address,
						ChainID: chainID, IsPrimary: true, CreatedAt: now,
					})
				} else {
					userID = wallet.UserID
				}
				sess, err := c.Auth.NewSession(c, userID, true)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				user, _ := c.Auth.Store().FindUserByID(c.R.Context(), userID)
				c.WriteJSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
			}),
		},
	}
}

func siweNonceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		nonce, _ := id.Generate(16)
		_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationSIWENonce+nonce, nonce, 10*time.Minute)
		c.WriteJSON(http.StatusOK, map[string]string{"nonce": nonce})
	}
}

package auth

import (
	"encoding/json"
	"net/http"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
)

const codePhoneNumberCannotBeUpdated = "PHONE_NUMBER_CANNOT_BE_UPDATED"

func (a *Auth) phoneNumberPluginEnabled() bool {
	for _, plugin := range a.cfg.plugins {
		if plugin.ID() == constants.PluginPhoneNumber {
			return true
		}
	}
	return false
}

func (a *Auth) phoneNumberAdditionalFromRaw(raw map[string]json.RawMessage) (map[string]any, *apierror.Error) {
	if !a.phoneNumberPluginEnabled() {
		return nil, nil
	}
	value, ok := raw[constants.FieldPhoneNumber]
	if !ok {
		return nil, nil
	}
	if string(value) != "null" {
		return nil, apierror.New(http.StatusBadRequest, codePhoneNumberCannotBeUpdated, "Phone number cannot be updated")
	}
	return map[string]any{
		constants.FieldPhoneNumber:   nil,
		constants.FieldPhoneVerified: false,
	}, nil
}

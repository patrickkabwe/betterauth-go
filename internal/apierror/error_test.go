package apierror_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
)

func TestErrorJSON(t *testing.T) {
	err := apierror.New(http.StatusBadRequest, constants.CodeInvalidField, constants.MsgInvalidField)
	rr := httptest.NewRecorder()
	apierror.WriteJSON(rr, err)
	if rr.Code != http.StatusBadRequest {
		t.Fatal("status")
	}
	var body map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["code"] != constants.CodeInvalidField {
		t.Fatal("code mismatch")
	}
	if err.Error() != constants.MsgInvalidField {
		t.Fatal("error string")
	}
}

func TestWithCode(t *testing.T) {
	err := apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail)
	if err.Code != constants.CodeInvalidEmail || err.Message != constants.MsgInvalidEmail {
		t.Fatal("with code mismatch")
	}
}

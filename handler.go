package oauth2fiber

import (
	// "net/http"

	"encoding/base64"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/gofiber/fiber/v2"
)

type (
	// ClientInfoHandler get client info from request
	ClientInfoHandler func(c *fiber.Ctx) (clientID, clientSecret string, err error)

	// ClientAuthorizedHandler check the client allows to use this authorization grant type
	ClientAuthorizedHandler func(clientID string, grant oauth2.GrantType) (allowed bool, err error)

	// ClientScopeHandler check the client allows to use scope
	ClientScopeHandler func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error)

	// UserAuthorizationHandler get user id from request authorization
	UserAuthorizationHandler func(c *fiber.Ctx) (userID string, err error)

	// PasswordAuthorizationHandler get user id from username and password
	PasswordAuthorizationHandler func(username string, password string, clientId ...string) (userID string, err error)

	// RefreshingScopeHandler check the scope of the refreshing token
	RefreshingScopeHandler func(tgr *oauth2.TokenGenerateRequest, oldScope string) (allowed bool, err error)

	// RefreshingValidationHandler check if refresh_token is still valid. eg no revocation or other
	RefreshingValidationHandler func(ti oauth2.TokenInfo) (allowed bool, err error)

	// ResponseErrorHandler response error handing
	ResponseErrorHandler func(re *errors.Response)

	// InternalErrorHandler internal error handing
	InternalErrorHandler func(err error) (re *errors.Response)

	// AuthorizeScopeHandler set the authorized scope
	AuthorizeScopeHandler func(c *fiber.Ctx) (scope string, err error)

	// AccessTokenExpHandler set expiration date for the access token
	AccessTokenExpHandler func(c *fiber.Ctx) (exp time.Duration, err error)

	// ExtensionFieldsHandler in response to the access token with the extension of the field
	ExtensionFieldsHandler func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{})

	// ResponseTokenHandler response token handing
	ResponseTokenHandler func(c *fiber.Ctx, data map[string]interface{}, header map[string][]string, statusCode ...int) error
)

type _ClientForm struct {
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
}

// ClientFormHandler get client data from form
func ClientFormHandler(c *fiber.Ctx) (string, string, error) {
	client := new(_ClientForm)
	if err := c.BodyParser(client); err != nil {
		return "", "", err
	}
	if client.ClientID == "" {
		return "", "", errors.ErrInvalidClient
	}
	return client.ClientID, client.ClientSecret, nil
}

func ClientBasicHandler(c *fiber.Ctx) (string, string, error) {
	if auth := c.Get("Authorization"); auth != "" {
		if username, password, ok := parseBasicAuth(auth); ok {
			return username, password, nil
		}
	}
	return "", "", errors.ErrInvalidClient
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func EqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

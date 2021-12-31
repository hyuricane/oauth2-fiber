package oauth2fiber_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gavv/httpexpect"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/gofiber/fiber/v2"
	oauth2fiber "github.com/hyuricane/oauth2-fiber"
)

var (
	srv          *oauth2fiber.Server
	tsrv         *httptest.Server
	manager      *manage.Manager
	csrv         *httptest.Server
	clientID     = "111111"
	clientSecret = "11111111"

	plainChallenge = "ThisIsAFourtyThreeCharactersLongStringThing"
	s256Challenge  = "s256test"
	// echo s256test | sha256 | base64 | tr '/+' '_-'
	s256ChallengeHash = "W6YWc_4yHwYN-cGDgGmOMHF3l7KDy7VcRjf7q2FVF-o="
)

func init() {
	manager = manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())
}

func clientStore(domain string) oauth2.ClientStore {
	clientStore := store.NewClientStore()
	clientStore.Set(clientID, &models.Client{
		ID:     clientID,
		Secret: clientSecret,
		Domain: domain,
	})
	return clientStore
}

func testServer(t *testing.T, rw http.ResponseWriter, r *http.Request) {
	app := fiber.New()
	defer app.Shutdown()
	app.Use("/authorize", srv.HandleAuthorizeRequest)
	app.Use("/token", srv.HandleTokenRequest)
	var err error
	var resp *http.Response
	switch r.URL.Path {
	case "/authorize":
		resp, err = app.Test(r, 3000)
	case "/token":
		resp, err = app.Test(r, 3000)
	default:
		t.Logf("unexpected path: %s", r.URL.Path)
	}

	if err != nil {
		t.Error(err)
	} else if resp != nil {
		for k, v := range resp.Header {
			rw.Header().Set(k, v[0])
		}
		rw.WriteHeader(resp.StatusCode)
		io.Copy(rw, resp.Body)
		resp.Body.Close()
	}
}

func TestAuthorizeCode(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "12345" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL))

	srv = oauth2fiber.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(c *fiber.Ctx) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "12345").
		WithQuery("redirect_uri", url.QueryEscape(csrv.URL+"/oauth2")).
		Expect().Status(http.StatusOK)
}

func TestAuthorizeCodeWithChallengePlain(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}

			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithFormField("code", code).
				WithHeader("X-DEBUG", "token").
				WithBasicAuth("code_verifier", "testchallenge").
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL))
	srv = oauth2fiber.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(c *fiber.Ctx) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", url.QueryEscape(csrv.URL+"/oauth2")).
		WithQuery("code_challenge", plainChallenge).
		Expect().Status(http.StatusOK)
}

func TestAuthorizeCodeWithChallengeS256(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()

	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			resObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithFormField("code", code).
				WithBasicAuth("code_verifier", s256Challenge).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL))
	srv = oauth2fiber.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(c *fiber.Ctx) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", url.QueryEscape(csrv.URL+"/oauth2")).
		WithQuery("code_challenge", s256ChallengeHash).
		WithQuery("code_challenge_method", "S256").
		Expect().Status(http.StatusOK)
}

func TestImplicit(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL))
	srv = oauth2fiber.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(c *fiber.Ctx) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "token").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", url.QueryEscape(csrv.URL+"/oauth2")).
		Expect().Status(http.StatusOK)
}

func TestPasswordCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore(""))
	srv = oauth2fiber.NewDefaultServer(manager)
	srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
		if username == "admin" && password == "123456" {
			userID = "000000"
			return
		}
		err = fmt.Errorf("user not found")
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("username", "admin").
		WithFormField("password", "123456").
		WithFormField("scope", "all").
		WithBasicAuth(clientID, clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw())
}

func TestClientCredentials(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	manager.MapClientStorage(clientStore(""))

	srv = oauth2fiber.NewDefaultServer(manager)
	srv.SetClientInfoHandler(oauth2fiber.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		t.Log("OAuth 2.0 Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		t.Log("Response Error:", re.Error)
	})

	srv.SetAllowedGrantType(oauth2.ClientCredentials)
	srv.SetAllowGetAccessRequest(false)
	srv.SetExtensionFieldsHandler(func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{}) {
		fieldsValue = map[string]interface{}{
			"extension": "param",
		}
		return
	})
	srv.SetAuthorizeScopeHandler(func(c *fiber.Ctx) (scope string, err error) {
		return
	})
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "client_credentials").
		WithFormField("scope", "all").
		WithFormField("client_id", clientID).
		WithFormField("client_secret", clientSecret).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	t.Logf("%#v\n", resObj.Raw())

	validationAccessToken(t, resObj.Value("access_token").String().Raw())
}

func TestRefreshing(t *testing.T) {
	tsrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer tsrv.Close()
	e := httpexpect.New(t, tsrv.URL)

	csrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2":
			r.ParseForm()
			code, state := r.Form.Get("code"), r.Form.Get("state")
			if state != "123" {
				t.Error("unrecognized state:", state)
				return
			}
			jresObj := e.POST("/token").
				WithFormField("redirect_uri", csrv.URL+"/oauth2").
				WithFormField("code", code).
				WithFormField("grant_type", "authorization_code").
				WithFormField("client_id", clientID).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", jresObj.Raw())

			validationAccessToken(t, jresObj.Value("access_token").String().Raw())

			resObj := e.POST("/token").
				WithFormField("grant_type", "refresh_token").
				WithFormField("scope", "one").
				WithFormField("refresh_token", jresObj.Value("refresh_token").String().Raw()).
				WithBasicAuth(clientID, clientSecret).
				Expect().
				Status(http.StatusOK).
				JSON().Object()

			t.Logf("%#v\n", resObj.Raw())

			validationAccessToken(t, resObj.Value("access_token").String().Raw())
		}
	}))
	defer csrv.Close()

	manager.MapClientStorage(clientStore(csrv.URL))
	srv = oauth2fiber.NewDefaultServer(manager)
	srv.SetUserAuthorizationHandler(func(c *fiber.Ctx) (userID string, err error) {
		userID = "000000"
		return
	})

	e.GET("/authorize").
		WithQuery("response_type", "code").
		WithQuery("client_id", clientID).
		WithQuery("scope", "all").
		WithQuery("state", "123").
		WithQuery("redirect_uri", url.QueryEscape(csrv.URL+"/oauth2")).
		Expect().Status(http.StatusOK)
}

// validation access token
func validationAccessToken(t *testing.T, accessToken string) {
	app := fiber.New()
	defer app.Shutdown()

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	app.Use("/", func(c *fiber.Ctx) (err error) {
		ti, err := srv.ValidationBearerToken(c)
		if err != nil {
			t.Error(err.Error())
			return
		}
		if ti.GetClientID() != clientID {
			t.Error("invalid access token")
		}
		return
	})

	app.Test(req)

}

package negroni_middleware

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"testing"

	"github.com/dscottboggs/attest"
	auth "github.com/dscottboggs/go-middleware-session-auth"
	"github.com/gorilla/sessions"
)

const (
	testUsername = "test username"
	testPassword = "test password"
)

var (
	authorizedCallbackCalled,
	unAuthorizedCallbackCalled bool
	authorizedCallback, unAuthorizedCallback http.HandlerFunc
	user                                     auth.Username
	response                                 = []byte("OK.\r\n")
	key                                      = []byte("test session key")
)

func TestMain(m *testing.M) {
	authorizedCallback = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			authorizedCallbackCalled = true
			w.Write(response)
		},
	)
	unAuthorizedCallback = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			unAuthorizedCallbackCalled = true
			w.Write(response)
		},
	)
	auth.ConfigLocation = path.Join(
		os.TempDir(),
		"go-middleware-session-auth.test.conf",
	)
	if err := auth.CreateNewUser(testUsername, testPassword); err != nil {
		log.Fatal(err)
	}
	exitCode := m.Run()
	user = auth.Username(testUsername)
	if err := user.Delete(testPassword); err != nil {
		log.Fatal(err)
	}
	os.Exit(exitCode)
}

func TestSignIn(t *testing.T) {
	t.Run("with specified key", func(st *testing.T) {
		st.Run("successful case", func(st *testing.T) {
			test := attest.NewTest(st)
			unAuthorizedCallbackCalled = false
			authorizedCallbackCalled = false
			rec, req := test.NewRecorder(
				fmt.Sprintf(
					"/login?user=%s&token=%s",
					url.QueryEscape(testUsername),
					url.QueryEscape(testPassword),
				),
			)
			NewSignIn().
				WithSpecifiedKey(key).
				WhenUnauthorized(unAuthorizedCallback).
				ServeHTTP(rec, req, authorizedCallback)
			if unAuthorizedCallbackCalled {
				test.Error(`the "unauthorized" callback was called.`)
			}
			if !authorizedCallbackCalled {
				test.Error(`the "authorized" callback was not called.`)
			}
			res := rec.Result()
			test.Equals(http.StatusOK, res.StatusCode)
			body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
			for i, b := range body {
				test.Equals(response[i], b)
			}
			session, err := sessionStore.Get(req, SessionTokenCookie)
			test.Handle(err)
			token := session.Values[UserAuthSessionKey]
			test.NotNil(token, "got nil session key")
			test.TypeIs("string", token)
		})
		st.Run("no user info present", func(st *testing.T) {
			test := attest.New(st)
			unAuthorizedCallbackCalled = false
			authorizedCallbackCalled = false
			rec, req := test.NewRecorder()
			NewSignIn().
				WithSpecifiedKey(key).
				WhenUnauthorized(unAuthorizedCallback).
				ServeHTTP(rec, req, authorizedCallback)
			if authorizedCallbackCalled {
				test.Error(`the "authorized" callback was called`)
			}
			if !unAuthorizedCallbackCalled {
				test.Error(`the "unauthorized" callback was not called.`)
			}
			res := rec.Result()
			test.Equals(http.StatusOK, res.StatusCode)
			body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
			for i, b := range body {
				test.Equals(response[i], b)
			}
		})
		st.Run("incorrect password", func(st *testing.T) {
			test := attest.NewTest(st)
			unAuthorizedCallbackCalled = false
			authorizedCallbackCalled = false
			rec, req := test.NewRecorder(
				fmt.Sprintf(
					"/login?user=%s&token=%s",
					url.QueryEscape(testUsername),
					url.QueryEscape("incorrect password"),
				),
			)
			NewSignIn().
				WithSpecifiedKey(key).
				WhenUnauthorized(unAuthorizedCallback).
				ServeHTTP(rec, req, authorizedCallback)
			if authorizedCallbackCalled {
				test.Error(`the "authorized" callback was called`)
			}
			if !unAuthorizedCallbackCalled {
				test.Error(`the "unauthorized" callback was not called.`)
			}
			res := rec.Result()
			test.Equals(http.StatusOK, res.StatusCode)
			body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
			for i, b := range body {
				test.Equals(response[i], b)
			}
		})

	})
}

func TestSession(t *testing.T) {
	t.Run("with specified key", func(st *testing.T) {
		t.Run("success case", func(st *testing.T) {
			test := attest.NewTest(st)
			rec, req := test.NewRecorder()
			session, err := sessionStore.Get(req, SessionTokenCookie)
			test.Handle(err)
			token := auth.NewSession()
			session.Values[UserAuthSessionKey] = token
			unAuthorizedCallbackCalled = false
			authorizedCallbackCalled = false
			SessionAuth(unAuthorizedCallback).
				ServeHTTP(rec, req, authorizedCallback)
			if unAuthorizedCallbackCalled {
				test.Error(`the "unauthorized" callback was called.`)
			}
			if !authorizedCallbackCalled {
				test.Error(`the "authorized" callback was not called.`)
			}
			res := rec.Result()
			test.Equals(http.StatusOK, res.StatusCode)
			body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
			for i, b := range body {
				test.Equals(response[i], b)
			}
			test.Equals(
				token,
				test.EatError(
					sessionStore.Get(req, SessionTokenCookie),
				).(*sessions.Session).Values[UserAuthSessionKey],
			)
		})
		t.Run("session not valid", func(t *testing.T) {
			test := attest.New(t)
			rec, req := test.NewRecorder()
			authorizedCallbackCalled = false
			unAuthorizedCallbackCalled = false
			session, err := sessionStore.Get(req, SessionTokenCookie)
			test.Handle(err)
			session.Values[UserAuthSessionKey] = "invalid token"
			SessionAuth(unAuthorizedCallback).
				ServeHTTP(rec, req, authorizedCallback)
			if !unAuthorizedCallbackCalled {
				test.Error(`the "unauthorized" callback was not called.`)
			}
			if authorizedCallbackCalled {
				test.Error(`the "authorized" callback was called.`)
			}
			res := rec.Result()
			body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
			for i, b := range body {
				test.Equals(response[i], b)
			}
		})
		t.Run("no session at all", func(t *testing.T) {
			test := attest.New(t)
			rec, req := test.NewRecorder()
			unAuthorizedCallbackCalled = false
			authorizedCallbackCalled = false
			SessionAuth(unAuthorizedCallback).
				ServeHTTP(rec, req, authorizedCallback)
			if !unAuthorizedCallbackCalled {
				test.Error(`the "unauthorized" callback was not called.`)
			}
			if authorizedCallbackCalled {
				test.Error(`the "authorized" callback was called.`)
			}
			res := rec.Result()
			body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
			for i, b := range body {
				test.Equals(response[i], b)
			}
		})
	})
}

func TestFullFlow(t *testing.T) {
	test := attest.NewTest(t)
	// Sign the user in
	unAuthorizedCallbackCalled = false
	authorizedCallbackCalled = false
	rec, req := test.NewRecorder(
		fmt.Sprintf(
			"/login?user=%s&token=%s",
			url.QueryEscape(testUsername),
			url.QueryEscape(testPassword),
		),
	)
	si := NewSignIn().
		WithSpecifiedKey(key).
		WhenUnauthorized(unAuthorizedCallback)
	sh := SessionAuth()
	sh.LoginHandler = http.HandlerFunc(func(r http.ResponseWriter, w *http.Request) {
		si.ServeHTTP(w, r, sh.LoginHandler)
	})

	if !authenticatedCallbackCalled {
		test.Error(`the "authenticated" callback was not called.`)
	}
	if unAuthorizedCallbackCalled {
		test.Error(`the "unauthorized" callback was called.`)
	}
	// check the response
	res = rec.Result()
	test.Equals(http.StatusOK, res.StatusCode)
	body = test.EatError(ioutil.ReadAll(res.Body)).([]byte)
	if len(body) == len(response) {
		for i, b := range response {
			test.Equals(body[i], b)
		}
	} else {
		test.Errorf(`got unexpected body "%s"`, string(body))
	}
}

package middleware

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/dscottboggs/attest"
	auth "github.com/dscottboggs/go-middleware-session-auth"
)

func TestSesssionAuthenticationMiddleware(t *testing.T) {
	t.Run("has session", func(t *testing.T) {
		test := attest.New(t)
		rec, req := test.NewRecorder()
		session, err := store.Get(req, SessionTokenCookie)
		test.Handle(err)
		session.Values[UserAuthSessionKey] = auth.NewSession()
		var nextHasBeenCalled bool
		SessionAuthentication(
			http.HandlerFunc(
				func(arg1 http.ResponseWriter, arg2 *http.Request) {
					nextHasBeenCalled = true
				},
			),
		)(rec, req)
		if !nextHasBeenCalled {
			test.Error(`"next" was not called!`)
		}
	})
	t.Run("session is not valid", func(t *testing.T) {
		test := attest.New(t)
		rec, req := test.NewRecorder()
		session, err := store.Get(req, SessionTokenCookie)
		test.Handle(err)
		session.Values[UserAuthSessionKey] = "invalid token"
		var nextHasBeenCalled bool
		SessionAuthentication(
			http.HandlerFunc(
				func(arg1 http.ResponseWriter, arg2 *http.Request) {
					nextHasBeenCalled = true
				},
			),
		)(rec, req)
		if nextHasBeenCalled {
			test.Error(`"next" was called!`)
		}
		res := rec.Result()
		test.Equals(http.StatusTemporaryRedirect, res.StatusCode)
		test.Equals("/login", test.EatError(res.Location()).(*url.URL).Path)
	})
	t.Run("no session present", func(t *testing.T) {
		test := attest.New(t)
		rec, req := test.NewRecorder()
		var nextHasBeenCalled bool
		SessionAuthentication(
			http.HandlerFunc(
				func(arg1 http.ResponseWriter, arg2 *http.Request) {
					nextHasBeenCalled = true
				},
			),
		)(rec, req)
		if nextHasBeenCalled {
			test.Error(`"next" was called!`)
		}
		res := rec.Result()
		test.Equals(http.StatusTemporaryRedirect, res.StatusCode)
		test.Equals("/login", test.EatError(res.Location()).(*url.URL).Path)
	})
}

func TestOneShotFullFlow(t *testing.T) {
	var (
		nextHasBeenCalled, loginHandlerHasBeenCalled bool
		handler                                      = SessionAuthentication(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextHasBeenCalled = true
				w.Write(response)
			}),
		)
		reset = func() {
			nextHasBeenCalled = false
			loginHandlerHasBeenCalled = false
		}
	)
	LoginHandler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			loginHandlerHasBeenCalled = true
			w.Write(response)
		},
	)
	t.Run("with no authentication provided", func(t *testing.T) {
		test := attest.New(t)
		reset()
		rec, req := test.NewRecorder()
		handler(rec, req)
		res := rec.Result()
		if !loginHandlerHasBeenCalled {
			t.Error(`the "login" callback was not called`)
		}
		if nextHasBeenCalled {
			t.Error(`the "next" callback was called`)
		}
		test.Equals(http.StatusOK, res.StatusCode)
		body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
		for i, b := range body {
			test.Equals(response[i], b)
		}
	})
	t.Run("with valid login but no session", func(t *testing.T) {
		test := attest.NewTest(t)
		reset()
		rec, req := test.NewRecorder(fmt.Sprintf(
			`/test?user=%s&token=%s`,
			url.QueryEscape(testUsername),
			url.QueryEscape(testPassword),
		))
		handler(rec, req)
		res := rec.Result()
		if loginHandlerHasBeenCalled {
			t.Error(`the "login" callback was called`)
		}
		if !nextHasBeenCalled {
			t.Error(`the "next" callback was not called`)
		}
		test.Equals(http.StatusOK, res.StatusCode)
		body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
		for i, b := range body {
			test.Equals(response[i], b)
		}
	})
	t.Run("with valid session", func(t *testing.T) {
		test := attest.NewTest(t)
		reset()
		rec, req := test.NewRecorder()
		token := auth.NewSession()
		sesh, err := store.Get(req, SessionTokenCookie)
		test.Handle(err)
		sesh.Values[UserAuthSessionKey] = token
		sesh.Save(req, rec)
		handler(rec, req)
		res := rec.Result()
		if loginHandlerHasBeenCalled {
			t.Error(`the "login" callback was called`)
		}
		if !nextHasBeenCalled {
			t.Error(`the "next" callback was not called`)
		}
		test.Equals(http.StatusOK, res.StatusCode)
		body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
		for i, b := range body {
			test.Equals(response[i], b)
		}
	})
}

package gorilla_middleware

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
		token, _ := auth.NewSession()
		session.Values[UserAuthSessionKey] = token
		var nextHasBeenCalled bool
		sessionAuthentication(
			http.HandlerFunc(
				func(arg1 http.ResponseWriter, arg2 *http.Request) {
					nextHasBeenCalled = true
				},
			),
		).ServeHTTP(rec, req)
		if !nextHasBeenCalled {
			test.Error(`"next" was not called!`)
		}
	})
	t.Run("session is not valid", func(t *testing.T) {
		test := attest.New(t)
		rec, req := test.NewRecorder()
		session, err := store.Get(req, SessionTokenCookie)
		test.Handle(err)
		invalidToken, _ := auth.NewSession()
		invalidToken.Delete()
		if invalidToken.CurrentlyExists() {
			t.Error("token existed after deletion")
		}
		session.Values[UserAuthSessionKey] = invalidToken
		var nextHasBeenCalled bool
		sessionAuthentication(
			http.HandlerFunc(
				func(arg1 http.ResponseWriter, arg2 *http.Request) {
					nextHasBeenCalled = true
				},
			),
		).ServeHTTP(rec, req)
		if nextHasBeenCalled {
			test.Error(`"next" was called!`)
		}
		res := rec.Result()
		defer res.Body.Close()
		test.Equals(http.StatusUnauthorized, res.StatusCode)
		body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
		test.Equals(
			fmt.Sprintf("%d Unauthorized", http.StatusUnauthorized),
			string(body),
		)
	})
	t.Run("no session present", func(t *testing.T) {
		test := attest.New(t)
		rec, req := test.NewRecorder()
		var nextHasBeenCalled bool
		sessionAuthentication(
			http.HandlerFunc(
				func(arg1 http.ResponseWriter, arg2 *http.Request) {
					nextHasBeenCalled = true
				},
			),
		).ServeHTTP(rec, req)
		if nextHasBeenCalled {
			test.Error(`"next" was called!`)
		}
		res := rec.Result()
		defer res.Body.Close()
		test.Equals(http.StatusUnauthorized, res.StatusCode)
		body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
		test.Equals(
			fmt.Sprintf("%d Unauthorized", http.StatusUnauthorized),
			string(body),
		)
	})
}

func TestOneShotFullFlow(t *testing.T) {
	var (
		nextHasBeenCalled, loginHandlerHasBeenCalled bool
		handler                                      = sessionAuthentication(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextHasBeenCalled = true
				w.Write(response)
			}),
		).ServeHTTP
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
		defer res.Body.Close()
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
		defer res.Body.Close()
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
		token, _ := auth.NewSession()
		sesh, err := store.Get(req, SessionTokenCookie)
		test.Handle(err)
		sesh.Values[UserAuthSessionKey] = token
		sesh.Save(req, rec)
		handler(rec, req)
		res := rec.Result()
		defer res.Body.Close()
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

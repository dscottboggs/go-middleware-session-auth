package middleware

import (
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
		SessionAuthenticationMiddleware(
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
		SessionAuthenticationMiddleware(
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
		SessionAuthenticationMiddleware(
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

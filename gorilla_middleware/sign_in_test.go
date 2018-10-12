package middleware

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
)

func TestMain(m *testing.M) {
	store = sessions.NewCookieStore([]byte("test session key"))
	auth.ConfigLocation = path.Join(
		os.TempDir(),
		"go-middleware-session-auth.test.conf",
	)
	if err := auth.CreateNewUser(testUsername, testPassword); err != nil {
		log.Fatal(err)
	}
	user = auth.Username(testUsername)
	unAuthorizedCallback = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			unAuthorizedCallbackCalled = true
			w.Write(response)
		},
	)
	authorizedCallback = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			authorizedCallbackCalled = true
			w.Write(response)
		},
	)
	exitCode := m.Run()
	if err := user.Delete(testPassword); err != nil {
		log.Fatal(err)
	}
	os.Exit(exitCode)
}

func TestSignInHandler(t *testing.T) {
	t.Run("successful sign in", func(st *testing.T) {
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
		signInHandler(authorizedCallback, unAuthorizedCallback)(rec, req)
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
		session, err := store.Get(req, SessionTokenCookie)
		test.Handle(err)
		token := session.Values[UserAuthSessionKey]
		test.NotNil(token, "got nil session key")
		test.TypeIs("string", token)
	})
	t.Run("no params present", func(st *testing.T) {
		test := attest.NewTest(st)
		unAuthorizedCallbackCalled = false
		authorizedCallbackCalled = false
		rec, req := test.NewRecorder()
		signInHandler(authorizedCallback, unAuthorizedCallback)(rec, req)
		if !unAuthorizedCallbackCalled {
			test.Error(`the "unauthorized" callback was not called.`)
		}
		if authorizedCallbackCalled {
			test.Error(`the "authorized" callback was called.`)
		}
		res := rec.Result()
		test.Equals(http.StatusOK, res.StatusCode)
		body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
		for i, b := range body {
			test.Equals(response[i], b)
		}
	})
	t.Run("valid user but invalid password", func(st *testing.T) {
		test := attest.NewTest(st)
		unAuthorizedCallbackCalled = false
		authorizedCallbackCalled = false
		rec, req := test.NewRecorder(
			fmt.Sprintf(
				"/login?user=%s&token=%s",
				url.QueryEscape(testUsername),
				url.QueryEscape("invalid password"),
			),
		)
		signInHandler(authorizedCallback, unAuthorizedCallback)(rec, req)
		if !unAuthorizedCallbackCalled {
			test.Error(`the "unauthorized" callback was not called.`)
		}
		if authorizedCallbackCalled {
			test.Error(`the "authorized" callback was called.`)
		}
		res := rec.Result()
		test.Equals(http.StatusOK, res.StatusCode)
		body := test.EatError(ioutil.ReadAll(res.Body)).([]byte)
		for i, b := range body {
			test.Equals(response[i], b)
		}
	})
}

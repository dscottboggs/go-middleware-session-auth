package auth

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/dscottboggs/attest"
)

func TestIsAllowed(t *testing.T) {
	test := attest.NewTest(t)
	token := NewSession()
	authCookie := http.Cookie{
		Name:  SessionTokenCookie,
		Value: token,
	}
	test.Run("valid session", func(st *testing.T) {
		subtest := attest.NewTest(st)
		rec, req := subtest.NewRecorder("/")
		req.AddCookie(&authCookie)
		if !subtest.EatError(IsAllowed(rec, req)).(bool) {
			subtest.Error("request is not allowed\n")
		}
	})
	test.Run("without session cookie", func(st *testing.T) {
		subtest := attest.NewTest(t)
		rec, req := subtest.NewRecorder("/")
		ok, err := IsAllowed(rec, req)
		subtest.NotNil(
			err,
			"error from IsAllowed when passed request with no cookie was nil\n",
		)
		if ok {
			subtest.Error("IsAllowed returned true for request with no cookie\n")
		}
	})
	Delete(token)
	test.Run("without valid token", func(st *testing.T) {
		subtest := attest.New(t)
		rec, req := subtest.NewRecorder("/")
		req.AddCookie(&authCookie)
		if subtest.EatError(IsAllowed(rec, req)).(bool) {
			subtest.Error("request is allowed\n")
		}
	})
}

func TestSessionAuthentication(t *testing.T) {
	test := attest.NewTest(t)
	test.Run("valid session", func(st *testing.T) {
		subtest := attest.NewTest(t)
		token := NewSession()
		authCookie := http.Cookie{
			Name:  SessionTokenCookie,
			Value: token,
		}
		rec, req := subtest.NewRecorder("/")
		req.AddCookie(&authCookie)
		func(w http.ResponseWriter, r *http.Request) {
			if r == nil {
				return
			}
			w.Write([]byte("OK."))
		}(SessionAuthentication(rec, req))
		res := rec.Result()
		defer func() { res.Body.Close() }()
		subtest.ResponseOK(res)
		body := string(
			subtest.EatError(
				ioutil.ReadAll(res.Body),
			).([]byte),
		)
		subtest.Equals("OK.", body)
	})
	test.Run("invalid session", func(st *testing.T) {
		subtest := attest.NewTest(st)
		authCookie := http.Cookie{
			Name:  SessionTokenCookie,
			Value: "an invalid token value",
		}
		rec, req := subtest.NewRecorder("/")
		req.AddCookie(&authCookie)
		func(w http.ResponseWriter, r *http.Request) {
			if r == nil {
				return
			}
			w.Write([]byte("OK."))
		}(SessionAuthentication(rec, req))
		res := rec.Result()
		test.Equals(http.StatusTemporaryRedirect, res.StatusCode)
	})
	test.Run("without a cookie", func(st *testing.T) {
		subtest := attest.NewTest(st)
		rec, req := subtest.NewRecorder("/")
		func(w http.ResponseWriter, r *http.Request) {
			if r == nil {
				return
			}
			w.Write([]byte("OK."))
		}(SessionAuthentication(rec, req))
		res := rec.Result()
		if res.StatusCode != http.StatusTemporaryRedirect {
			subtest.Errorf(
				"got status code %d from invalidly authenticated request; "+
					"expected %d\n",
				res.StatusCode,
				http.StatusTemporaryRedirect,
			)
		}
	})
}

func TestSignIn(t *testing.T) {
	test := attest.NewTest(t)
	username, password := "test SignIn user", "test SignIn user's password"
	user := User(username)
	test.Handle(CreateNewUser(username, password))
	if !user.IsAuthenticatedBy(password) {
		test.Error("user is not authenticated by password.")
	}
	test.Run("with valid user", func(st *testing.T) {
		subtest := attest.NewTest(st)
		rec, req := subtest.NewRecorder("/login")
		req.Method = "POST"
		q := req.URL.Query()
		q.Set("user", username)
		q.Set("token", password)
		req.URL.RawQuery = q.Encode()
		SignIn(rec, req)
		res := rec.Result()
		if res.StatusCode != 301 {
			subtest.Errorf(
				"got status code %d from SignIn, expected 301",
				res.StatusCode,
			)
		}
		for _, cookie := range res.Cookies() {
			if cookie.Name == SessionTokenCookie {
				if !HasSession(cookie.Value) {
					subtest.Error("got false from HasSession after SignIn request.")
				}
				Delete(cookie.Value)
			}
		}
	})
	user.Delete(password)
	test.Run("after deleting user", func(st *testing.T) {
		subtest := attest.NewTest(st)
		rec, req := subtest.NewRecorder("/login")
		req.Method = "POST"
		f := make(url.Values)
		f.Set("user", username)
		f.Set("token", password)
		req.Form = f
		SignIn(rec, req)
		res := rec.Result()
		if res.StatusCode != 307 {
			subtest.Errorf(
				"got status code %d from SignIn, expected 307",
				res.StatusCode,
			)
		}
	})
}

func TestGetToken(t *testing.T) {
	var (
		test               = attest.New(t)
		username, password = "test GetToken user", "test GetToken user's password"
		user               = User(username)
	)
	test.Run("expected success case", func(st *testing.T) {
		var (
			subtest  = attest.New(st)
			rec, req = test.NewRecorder()
			f        = make(url.Values)
			token    Session
		)
		f.Set("user", username)
		f.Set("token", password)
		subtest.Handle(CreateNewUser(username, password))
		if !user.IsAuthenticatedBy(password) {
			subtest.Error("user failed authentication")
		}
		req.Form = f
		var tokenString = GetToken(rec, req)
		copy(token[:], []byte(tokenString))
		if !token.CurrentlyExists() {
			subtest.Error("token didn't work")
		}
	})
	test.Run("user authentication failure", func(st *testing.T) {
		var (
			subtest  = attest.New(st)
			rec, req = test.NewRecorder()
			f        = make(url.Values)
			token    Session
		)
		f.Set("user", username)
		f.Set("token", "incorrect password")
		if user.IsAuthenticatedBy("incorrect password") {
			subtest.Error("user failed authentication")
		}
		req.Form = f
		var tokenString = GetToken(rec, req)
		if tokenString != "" {
			subtest.Errorf("tokenString was %s", tokenString)
		}
		copy(token[:], []byte(tokenString))
		if HasSession(tokenString) {
			subtest.Error("session exists")
		}
		if token.CurrentlyExists() {
			subtest.Error("token was valid")
		}
	})
}

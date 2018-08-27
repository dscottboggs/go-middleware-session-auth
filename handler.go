package auth

import (
	"fmt"
	"net/http"
	"time"
)

const sessionTokenCookie = "session_token"

var dummyResponseWriter http.ResponseWriter

// SignIn with a username and password in the query string
func SignIn(w http.ResponseWriter, r *http.Request) {
	user := User(r.URL.Query().Get("user"))
	pass := r.URL.Query().Get("token")
	if !user.IsAuthenticatedBy(pass) {
		fmt.Printf("user %s failed to be authenticated with %s", user, pass)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token, err := NewSession()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	auth := http.Cookie{
		Name:    sessionTokenCookie,
		Value:   token,
		Expires: time.Now().Add(120 * time.Minute),
	}
	http.SetCookie(w, &auth)
}

// SessionAuthentication provides a middleware function for handling session
// authentication. It responds with an appropriate http status message and
// returns a nil request on failure, on success forwards the request and writer
// through unmodified.
func SessionAuthentication(
	w http.ResponseWriter, r *http.Request,
) (
	http.ResponseWriter, *http.Request,
) {
	cookie, err := r.Cookie(sessionTokenCookie)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return w, nil
	}
	if HasSession(cookie.Value) {
		return w, r
	}
	w.WriteHeader(http.StatusUnauthorized)
	return w, nil
}

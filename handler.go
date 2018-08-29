package auth

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

const sessionTokenCookie = "session_token"

var dummyResponseWriter http.ResponseWriter

// SignIn with a username and password in the query string
func SignIn(w http.ResponseWriter, r *http.Request) {
	var (
		user User
		pass string
	)
	if user = User(r.FormValue("user")); user == "" {
		user = User(r.URL.Query().Get("user"))
	}
	if pass = r.FormValue("token"); pass == "" {
		pass = r.URL.Query().Get("token")
	}
	if !user.IsAuthenticatedBy(pass) {
		fmt.Printf("user %s failed to be authenticated with %s", user, pass)
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
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
	http.Redirect(w, r, "/", 301)
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
	if IsUnauthenticatedEndpoint(r.URL.RawPath) {
		return w, r
	}
	cookie, err := r.Cookie(sessionTokenCookie)
	if err != nil {
		log.Printf("error getting cookie for %#+v", r.URL)
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return w, nil
	}
	if token := cookie.Value; HasSession(token) {
		// log.Printf("authentication successful for '%s'", r.URL.RawPath)
		// Delete(token)
		// if newtoken, err := NewSession(); err != nil {
		// 	panic(err)
		// } else {
		// 	http.SetCookie(w, &http.Cookie{
		// 		Name:    sessionTokenCookie,
		// 		Value:   newtoken,
		// 		Expires: time.Now().Add(2 * time.Hour),
		// 	})
		// }
		return w, r
	}
	log.Printf("authentication unsuccessful for '%s'", r.URL.RawPath)
	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
	return w, nil
}

// IsAllowed determines if a specific request is allowed to be served by
// session authentication. If the route is allowed without authentication or
// has a valid session token, true and nil are returned. If the cookie doesn't
// exist, false is returned along with an error saying so. Finally, in any other
// case (the case that an invalid authentication token is received), false is
// returned with a nil error.
func IsAllowed(w http.ResponseWriter, r *http.Request) (bool, error) {
	if IsUnauthenticatedEndpoint(r.URL.RawPath) {
		return true, nil
	}
	cookie, err := r.Cookie(sessionTokenCookie)
	if err != nil {
		return false, err
	}
	if token := cookie.Value; HasSession(token) {
		return true, nil
	}
	return false, nil
}

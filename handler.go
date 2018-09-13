package auth

import (
	"fmt"
	"log"
	"net/http"
)

const (
	// SessionTokenCookie -- The key that the session cookie is referenced by
	SessionTokenCookie = "session_token"
	// 90 days in seconds
	ninetyDays = 60 * 60 * 24 * 90
)

var dummyResponseWriter http.ResponseWriter

// SignIn with a username and password in the query string. If the optional
// query argument is set (to anything besides the empty string), the Max-Age
// cookie value will be excluded, which browsers by convention take to mean
// that the session should expire when the window/tab is closed. It would
// improve server-site performance if the client would request such a token be
// expired when such a session ends, as this library has no way of knowing when
// this event occurs, and therefore makes no effort aside from this cookie value
// to expire such a token, and it will remain in the valid key store until
// manually deleted (with Delete(token)) or it expires.
func SignIn(w http.ResponseWriter, r *http.Request) {
	var (
		user Username
		pass string
	)
	user = Username(r.FormValue("user")) // r.FormValue accepts post form or URL
	pass = r.FormValue("token")          // queries
	if !user.IsAuthenticatedBy(pass) {
		fmt.Printf("user %s failed to be authenticated with %s\n", user, pass)
		http.Redirect(w, r, "/login?failed=true", http.StatusTemporaryRedirect)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   SessionTokenCookie,
		Value:  NewSession(),
		MaxAge: ninetyDays,
	})
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect /* (307) */)
}

// GetToken acts like SignIn, but returns a status value to leave the
// action up to the calling function.
func GetToken(w http.ResponseWriter, r *http.Request) string {
	var (
		user Username
		pass string
	)
	user = Username(r.FormValue("user")) // r.FormValue accepts post form or URL
	pass = r.FormValue("token")          // queries
	if !user.IsAuthenticatedBy(pass) {
		return ""
	}
	token := NewSession()
	return token
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
	cookie, err := r.Cookie(SessionTokenCookie)
	if err != nil {
		log.Printf("error getting cookie for %#+v\n", r.URL)
		/*
			causes problems
				http.SetCookie(w, &http.Cookie{
					Name:   SessionTokenCookie,
					Value:  "",
					MaxAge: -1, // delete the cookie
				})
		*/
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return w, nil
	}
	if token := cookie.Value; HasSession(token) {
		return w, r
	}
	log.Printf("authentication unsuccessful for '%s'\n", r.URL.RawPath)
	/*
		causes problems
		http.SetCookie(w, &http.Cookie{
			Name:   SessionTokenCookie,
			Value:  "",
			MaxAge: -1, // delete the cookie
		})
	*/
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
	cookie, err := r.Cookie(SessionTokenCookie)
	if err != nil {
		for _, c := range r.Cookies() {
			log.Printf("got cookie: %#+v\n", c)
		}
		log.Printf("got cookies: %#+v\n", r.Cookies())
		return false, err
	}
	if token := cookie.Value; HasSession(token) {
		return true, nil
	}
	return false, nil
}

package gorilla_middleware

import (
	"log"
	"net/http"

	auth "github.com/dscottboggs/go-middleware-session-auth"
)

// delete the existing token and issue a new one.
func refreshToken(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	sesh, err := store.Get(r, SessionTokenCookie)
	if err != nil {
		log.Printf(
			"error getting session for authenticated user at '%s': %v\n",
			r.URL.RawPath,
			err,
		)
		LoginHandler(w, r)
		return
	}
	token := sesh.Values[UserAuthSessionKey]
	if token == nil {
		// this is actually unexpected.
		log.Printf("no token found in refreshToken! URL: '%s'.\n", r.URL.RawPath)
		LoginHandler(w, r)
		return
	}
	if !auth.HasSession(token.(string)) {
		// this too is unexpected but could happen maybe? regardless, be safe.
		log.Printf("unauthorized token in refreshToken! URL: '%s'.\n", r.URL.RawPath)
		LoginHandler(w, r)
		return
	}
	auth.Delete(token.(string))
	token = auth.NewSession()
	sesh.Values[UserAuthSessionKey] = token
	sesh.Save(r, w)
	next(w, r)
}

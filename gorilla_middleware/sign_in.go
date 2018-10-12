package gorilla_middleware

import (
	"fmt"
	"net/http"

	auth "github.com/dscottboggs/go-middleware-session-auth"
)

func signInHandler(authorized, unauthorized http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			user auth.Username
			pass string
		)
		user = auth.Username(r.FormValue("user")) // r.FormValue accepts post
		pass = r.FormValue("token")               // form or URL queries
		if !user.IsAuthenticatedBy(pass) {
			fmt.Printf("user %s failed to be authenticated with %s\n", user, pass)
			unauthorized(w, r)
			return
		}
		session, err := store.Get(r, SessionTokenCookie)
		if err != nil {
			fmt.Printf(
				"ERROR: user %s was successfully authenticated, but error %v "+
					"occurred trying to get the session\n",
				user,
				err,
			)
			// TODO perhaps do something different here?
			unauthorized(w, r)
			return
		}
		session.Values[UserAuthSessionKey] = auth.NewSession()
		if err = session.Save(r, w); err != nil {
			fmt.Printf(
				"ERROR: user %s was successfully authenticated, but error %v "+
					"occurred trying to get the session\n",
				user,
				err,
			)
			// TODO perhaps do something different here?
			unauthorized(w, r)
			return
		}
		session.Save(r, w)
		authorized(w, r)
	})
}

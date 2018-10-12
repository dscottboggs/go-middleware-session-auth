package middleware

import (
	"crypto/rand"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"

	auth "github.com/dscottboggs/go-middleware-session-auth"
	"github.com/gorilla/sessions"
)

var (
	store     *sessions.CookieStore
	configDir = path.Join(
		os.Getenv("HOME"),
		".config",
		"go-middleware-session-auth",
	)
	defaultSessionKeyLocation = path.Join(configDir, "session.key")
	bigInteger                = big.NewInt(1<<63 - 1)
	byteSize                  = big.NewInt(8)
	// LoginHandler --
	// requests are sent to the LoginHandler if authentication fails. By
	// default, it redirects to /login
	LoginHandler http.HandlerFunc
)

const (
	// SessionTokenCookie -- The key that the session is referenced by
	SessionTokenCookie = "session_token"
	// UserAuthSessionKey -- the key that the auth token is referenced by in the
	// session
	UserAuthSessionKey = "user_auth_session_key"
)

func init() {
	session_key_file := os.Getenv("go_middleware_session_key_file")
	var session_key []byte
	if session_key_file == "" {
		sk_str := os.Getenv("go_middleware_session_key")
		if sk_str == "" {
			// try default loc.
			session_key, err := ioutil.ReadFile(defaultSessionKeyLocation)
			if os.IsNotExist(err) {
				// check for config folder
				if _, err := os.Stat(defaultSessionKeyLocation); os.IsNotExist(err) {
					os.Mkdir(configDir, os.ModeDir|os.FileMode(0755))
				}
				// write new key to the default location and use that
				sk_file, err := os.Create(defaultSessionKeyLocation)
				if err != nil {
					log.Fatalf(
						"couldn't find a session key or create one at the default "+
							`location, "%s": %v`,
						defaultSessionKeyLocation,
						err,
					)
				}
				for i := 0; i < 32; /* 256 bits */ i++ {
					num, _ := rand.Int(rand.Reader, byteSize)
					if i > cap(session_key) {
						session_key = append(session_key, byte(num.Int64()))
					} else {
						session_key[i] = byte(num.Int64())
					}

				}
				_, err = sk_file.Write(session_key)
				if err != nil {
					log.Fatalf(
						"couldn't find a session key or create one at the default "+
							`location, "%s": %v`,
						defaultSessionKeyLocation,
						err,
					)
				}
			} else if err != nil {
				log.Fatalf(
					`error reading file at "%s": %v`,
					defaultSessionKeyLocation,
					err,
				)
			}
		} else {
			session_key = []byte(sk_str)
		}
	} else {
		var err error
		session_key, err = ioutil.ReadFile(session_key_file)
		if err != nil && !os.IsNotExist(err) {
			log.Fatalf(`error reading file at "%s": %v`, session_key_file, err)
		}
	}
	store = sessions.NewCookieStore(session_key)
	LoginHandler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		},
	)
}

// SessionAuthenticationMiddleware -- the middleware function that should be
// applied to a router for endpoints which require authentication.
func SessionAuthenticationMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, SessionTokenCookie)
		if err != nil {
			log.Printf(
				"error getting cookie for %s: %v\n",
				r.URL.String(),
				err,
			)
			LoginHandler(w, r)
			return
		}

		token := session.Values[UserAuthSessionKey]
		if token != nil && auth.HasSession(token.(string)) {
			next(w, r)
			return
		}
		log.Printf("authentication unsuccessful for '%s'\n", r.URL.RawPath)
		LoginHandler(w, r)
	})
}

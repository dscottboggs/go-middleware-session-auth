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
	store            *sessions.CookieStore
	defaultConfigDir = path.Join(
		os.Getenv("HOME"),
		".config",
		"go-middleware-session-auth",
	)
	defaultSessionKeyLocation = path.Join(defaultConfigDir, "session.key")
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
	UserAuthSessionKey = "user_auth_sessionKey"
)

func init() {
	sessionKeyFile := os.Getenv("go_middleware_session_key_file")
	var sessionKey []byte
	if sessionKeyFile == "" {
		keyString := os.Getenv("go_middleware_session_key")
		if keyString == "" {
			// try default loc.
			var err error
			sessionKey, err = ioutil.ReadFile(defaultSessionKeyLocation)
			if os.IsNotExist(err) {
				// check for config folder
				if _, err = os.Stat(defaultSessionKeyLocation); os.IsNotExist(err) {
					os.Mkdir(defaultConfigDir, os.ModeDir|os.FileMode(0755))
				}
				var keyFile *os.File
				// write new key to the default location and use that
				keyFile, err = os.Create(defaultSessionKeyLocation)
				if err != nil {
					log.Fatalf(
						"couldn't find a session key or create one at the default "+
							`location, "%s": %v`,
						defaultSessionKeyLocation,
						err,
					)
				}
				var num *big.Int
				for i := 0; i < 32; /* 256 bits */ i++ {
					num, err = rand.Int(rand.Reader, byteSize)
					if err != nil {
						// this seriously needs to break everything if it
						// doesn't work
						log.Fatalf(
							"failed to initialize random number generator: %v",
							err,
						)
					}
					if i > cap(sessionKey) {
						sessionKey = append(sessionKey, byte(num.Int64()))
					} else {
						sessionKey[i] = byte(num.Int64())
					}
				}
				_, err = keyFile.Write(sessionKey)
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
			sessionKey = []byte(keyString)
		}
	} else {
		var err error
		sessionKey, err = ioutil.ReadFile(sessionKeyFile)
		if err != nil && !os.IsNotExist(err) {
			log.Fatalf(`error reading file at "%s": %v`, sessionKeyFile, err)
		}
	}
	store = sessions.NewCookieStore(sessionKey)
	LoginHandler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		},
	)
}

func noSessionHandler(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc,
) {
	signInHandler(SessionAuthentication(next), LoginHandler)(w, r)
}

// SessionAuthentication returns a middleware which handles sign-in and session
// authentication on all endpoints. Usage:
//     router.Use(gorilla_middleware.SessionAuthentication)
//     gorilla_middleware.LoginHandler = renderLoginPage
// And that's it.
func SessionAuthentication(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, SessionTokenCookie)
		if err != nil {
			log.Printf(
				"error getting cookie for %s: %v\n",
				r.URL.String(),
				err,
			)
			noSessionHandler(w, r, next)
			return
		}
		token := session.Values[UserAuthSessionKey]
		if token != nil && auth.HasSession(token.(string)) {
			next(w, r)
			return
		}
		noSessionHandler(w, r, next)
	})
}

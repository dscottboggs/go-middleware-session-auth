package gorilla_middleware

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"
	"time"

	auth "github.com/dscottboggs/go-middleware-session-auth"
	"github.com/gorilla/mux"
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
	LoginHandler  http.HandlerFunc
	LogoutHandler = &LoginHandler
)

const (
	// SessionTokenCookie -- The key that the session is referenced by
	SessionTokenCookie = "session_token"
	// UserAuthSessionKey -- the key that the auth token is referenced by in the
	// session
	UserAuthSessionKey = "user_auth_sessionKey"
	oneWeek            = time.Second * 86400 * 7
)

func init() {
	gob.Register(&auth.Session{})
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
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "%d Unauthorized", http.StatusUnauthorized)
		},
	)
}

func noSessionHandler(
	w http.ResponseWriter, r *http.Request, next http.Handler,
) {
	signInHandler(
		sessionAuthentication(next).ServeHTTP,
		LoginHandler,
	)(w, r)
}

func sessionAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("logout") != "" {
			deauthorize(w, r, next)
			return
		}
		session, err := store.Get(r, SessionTokenCookie)
		if err != nil {
			log.Printf("error getting cookie for %s: %v\n", r.URL.String(), err)
			noSessionHandler(w, r, next)
			return
		}
		token := session.Values[UserAuthSessionKey]
		if token != nil {
			tkn := token.(auth.Session)
			if metadata, exists := tkn.GetMetadata(); exists {
				if metadata.Expiry.Unix() < time.Now().Unix() {
					// session is due for expiry but hasn't been cleaned up yet
					noSessionHandler(w, r, next)
				} else if metadata.Expiry.Unix() < time.Now().Add(oneWeek).Unix() {
					tkn, _ = auth.NewSession()
					session.Values[UserAuthSessionKey] = tkn
					session.Save(r, w)
					next.ServeHTTP(w, r)
					return
				} else {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		noSessionHandler(w, r, next)
	})
}

// SessionAuthentication returns a middleware which handles sign-in and session
// authentication on all endpoints. Usage:
// 	   // assuming you've written an http.HandlerFunc called renderLoginPage
//     // which renders a login page
//     router.Use(gorilla_middleware.SessionAuthentication(renderLoginPage))
// or
//     // to simply return "401 Unauthorized"
//     router.Use(gorilla_middleware.SessionAuthentication())
// And that's it.
func SessionAuthentication(login ...http.HandlerFunc) mux.MiddlewareFunc {
	switch numLoginHandlers := len(login); numLoginHandlers {
	case 0:
		// do nothing -- use the default of simply returning "401 Unauthorized"
	case 1:
		LoginHandler = login[0]
	default:
		log.Printf(
			"WARNING: %d login handlers specified, only the first will be used.\n",
			numLoginHandlers,
		)
		LoginHandler = login[0]
	}

	return mux.MiddlewareFunc(sessionAuthentication)
}

func deauthorize(w http.ResponseWriter, r *http.Request, next http.Handler) {
	session, err := store.Get(r, SessionTokenCookie)
	if err != nil {
		noSessionHandler(w, r, next)
	}
	token := session.Values[UserAuthSessionKey]
	if token == nil {
		noSessionHandler(w, r, next)
	}
	seshToken := token.(auth.Session)
	seshToken.Delete()
	(*LogoutHandler)(w, r)
}

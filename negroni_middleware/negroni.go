package negroni_middleware

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"

	auth "github.com/dscottboggs/go-middleware-session-auth"
	"github.com/gorilla/sessions"
)

const (
	// SessionTokenCookie -- The key that the session is referenced by
	SessionTokenCookie = "session_token"
	// UserAuthSessionKey -- the key that the auth token is referenced by in the
	// session
	UserAuthSessionKey = "user_auth_session_key"
)

var (
	defaultConfigDir = path.Join(
		os.Getenv("HOME"),
		".config",
		"go-middleware-session-auth",
	)
	defaultSessionKeyLocation = path.Join(defaultConfigDir, "session.key")
	byteSize                  = big.NewInt(1 << 8)
	sessionStore              *sessions.CookieStore
)

type signIn struct {
	unauthorizedHandler http.HandlerFunc
}

func (this *signIn) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc,
) {
	if sessionStore == nil {
		log.Fatal(
			"session store has not been set up. Call one of the " +
				"{Key,Keyfile,ForceNewKeyfile}Session() initializer functions")
	}
	var (
		user auth.Username
		pass string
	)
	user = auth.Username(r.FormValue("user")) // r.FormValue accepts post
	pass = r.FormValue("token")               // form or URL queries
	if !user.IsAuthenticatedBy(pass) {
		fmt.Printf("user %s failed to be authenticated with %s\n", user, pass)
		this.unauthorizedHandler(w, r)
		return
	}
	session, err := sessionStore.Get(r, SessionTokenCookie)
	if err != nil {
		fmt.Printf(
			"ERROR: user %s was successfully authenticated, but error %v "+
				"occurred trying to get the session\n",
			user,
			err,
		)
		// TODO perhaps do something different here?
		this.unauthorizedHandler(w, r)
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
		this.unauthorizedHandler(w, r)
		return
	}
	session.Save(r, w)
	next(w, r)
}

type sessionSettingsChainer struct{}

func (this *sessionSettingsChainer) WithKeyfile(
	keyfile string,
) *handlerSettingsChainer {
	keys, err := readKeyFrom(keyfile)
	if err != nil {
		keys = [][]byte{generateKey()}
		writeKeys(keyfile, keys...)
	}
	sessionStore = sessions.NewCookieStore(keys...)
	return &handlerSettingsChainer{}
}

func (this *sessionSettingsChainer) ForceNewKeyWithKeyfile(
	keyfile string,
) *handlerSettingsChainer {
	var keys [][]byte
	oldkeys, err := readKeyFrom(keyfile)
	if err != nil {
		keys = [][]byte{generateKey()}
	} else {
		keys = append([][]byte{generateKey()}, oldkeys...)
	}
	writeKeys(keyfile, keys...)
	sessionStore = sessions.NewCookieStore(keys...)
	return &handlerSettingsChainer{}
}

func (this *sessionSettingsChainer) WithSpecifiedKey(
	key []byte,
) *handlerSettingsChainer {
	sessionStore = sessions.NewCookieStore(key)
	return &handlerSettingsChainer{}
}

type handlerSettingsChainer struct{}

func (this *handlerSettingsChainer) WhenUnauthorized(
	unauthorized http.HandlerFunc,
) *signIn {
	return &signIn{
		unauthorizedHandler: unauthorized,
	}
}

func NewSignIn() *sessionSettingsChainer {
	return &sessionSettingsChainer{}
}

type Session struct {
	LoginHandler http.HandlerFunc
}

func SessionAuth(login http.HandlerFunc) *Session {
	return &Session{LoginHandler: login}
}

func (this *Session) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc,
) {
	if sessionStore == nil {
		log.Fatal(
			"session store has not been set up. Call one of the " +
				"{Key,Keyfile,ForceNewKeyfile}Session() initializer functions")
	}
	session, err := sessionStore.Get(r, SessionTokenCookie)
	if err != nil {
		log.Printf(
			"error getting cookie for %s: %v\n",
			r.URL.String(),
			err,
		)
		this.LoginHandler(w, r)
		return
	}
	token := session.Values[UserAuthSessionKey]
	if token != nil && auth.HasSession(token.(string)) {
		next(w, r)
		return
	}
	log.Printf("authentication unsuccessful for '%s'\n", r.URL.RawPath)
	this.LoginHandler(w, r)
}

func readKeyFrom(keyfile string) ([][]byte, error) {
	keys := make([][]byte, 1)
	file, err := os.Open(keyfile)
	if err != nil {
		return keys, err
	}
	gobreader := gob.NewDecoder(file)
	err = gobreader.Decode(keys)
	if err != nil {
		log.Fatalf(
			`error parsing gob for encryption keys at "%s": %v`,
			keyfile,
			err,
		)
	}
	return keys, nil
}

// generate a cryptographically secure encryption key
func generateKey() []byte {
	var key []byte
	for i := 0; i < 32; /* 256 bits */ i++ {
		num, err := rand.Int(rand.Reader, byteSize)
		if err != nil {
			// this seriously needs to break everything if it doesn't work
			log.Fatalf("failed to initialize random number generator: %v", err)
		}
		if i > cap(key) {
			key = append(key, byte(num.Int64()))
		} else {
			key[i] = byte(num.Int64())
		}
	}
	return key
}

func writeKeys(keyfile string, keys ...[]byte) {
	file, err := os.Create(keyfile)
	defer func() { file.Close() }()
	if err != nil {
		log.Fatalf(
			`error creating specified keyfile at "%s": %v`,
			keyfile,
			err,
		)
	}
	gobwriter := gob.NewEncoder(file)
	err = gobwriter.Encode(keys)
	if err != nil {
		log.Fatalf(
			`error writing keyfile at "%s": %v`,
			keyfile,
			err,
		)
	}
}

package negroni_middleware

import (
	"crypto/rand"
	"encoding/gob"
	"log"
	"math/big"
	"net/http"
	"os"
	"path"

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
	bigInteger                = big.NewInt(1<<63 - 1)
	byteSize                  = big.NewInt(8)
)

type NegroniSession struct {
	store        *sessions.CookieStore
	sessionKey   []byte
	LoginHandler http.HandlerFunc
}

func KeyfileSession(keyfile string, login http.HandlerFunc) *NegroniSession {
	keys := readKeyFrom(keyfile)
	sesh := NegroniSession{
		sessionKey:   keys[0],
		store:        sessions.NewCookieStore(keys...),
		LoginHandler: login,
	}

	return &sesh
}

func ForceNewKeyfileSession(keyfile string, login http.HandlerFunc) *NegroniSession {
	oldKeys := readKeyFrom(keyfile)
	newKey := generateKey()
	writeKeys(keyfile, newKey, oldKeys...)
}

func readKeyFrom(keyfile string) [][]byte {
	keys := make([][]byte, 1)
	file, err := os.Open(keyfile)
	if err == nil {
		gobreader := gob.NewDecoder(file)
		err := gobreader.Decode(keys)
		if err != nil {
			log.Fatalf(
				`error parsing gob for encryption keys at "%s": %v`,
				keyfile,
				err,
			)
		}
	} else {
		keys[0] = generateKey()
		writeKeys(keyfile, keys...)
	}
	return keys
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

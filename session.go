package auth

import (
	"time"

	random "github.com/dscottboggs/go-random-string"
)

const sessionKeyLength = 1 << 7

var expiryDelay = 2 * time.Hour

// The Session cookie store
type Session [sessionKeyLength]byte

// AllSessions stores each valid token
var AllSessions []Session

var nullSession Session

func init() {
	AllSessions = make([]Session, 0)
}

// HasSession returns true if the given token was found in AllSessions
func HasSession(token string) bool {
	if len(token) != sessionKeyLength {
		return false
	}
	var t Session
	copy(t[:], []byte(token))
	return hasSession(t)
}

func hasSession(token Session) bool {
	if token == nullSession {
		return false
	}
	for _, session := range AllSessions {
		if session == token {
			return true
		}
	}
	return false
}

func expire(token Session) {
	go func() {
		time.Sleep(expiryDelay)
		deleteToken(token)
	}()
}

// Delete the given token from the list of allowed sessions.
func (s *Session) Delete() {
	for index, token := range AllSessions {
		if (*s) == token {
			AllSessions = append(AllSessions[:index], AllSessions[index+1:]...)
		}
	}
}

// Delete the given token, given as a string.
func Delete(token string) {
	var ts Session
	copy(ts[:], []byte(token))
	ts.Delete()
}

// SetExpiryDelay changes the delay for session expiry from the default of 2 hours
func SetExpiryDelay(dTime time.Duration) {
	expiryDelay = dTime
}

// NewSession returns a new random token.
func NewSession() (string, error) {
	s, err := newSession()
	if err != nil {
		return "", err
	}
	AllSessions = append(AllSessions, s)
	expire(s)
	return string(s[:]), nil
}
func newSession() (Session, error) {
	var token Session
	for i := 0; i < sessionKeyLength; i++ {
		token[i] = byte(random.Alphanumeric())

	}
	if hasSession(token) {
		var err error
		token, err = newSession()
		if err != nil {
			return nullSession, err
		}
	}
	return token, nil
}

package auth

import (
	"time"

	random "github.com/dscottboggs/go-random-string"
)

const sessionKeyLength = 1 << 7

var expiryDelay = 24 * 90 * time.Hour

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
	return t.CurrentlyExists()
}

// CurrentlyExists --
// Checks that the given session token is present in the list of permitted
// sessions.
func (s *Session) CurrentlyExists() bool {
	if (*s) == nullSession {
		return false
	}
	for _, session := range AllSessions {
		if session == (*s) {
			return true
		}
	}
	return false
}

// Expire the session after the default period.
func (s *Session) Expire() {
	s.ExpireIn(expiryDelay)
}

// ExpireIn the given delay.
func (s *Session) ExpireIn(delay time.Duration) {
	go func() {
		time.Sleep(delay)
		s.Delete()
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
func NewSession() string {
	s := newSession()
	return string(s[:])
}
func newSession() Session {
	var token Session
	for i := 0; i < sessionKeyLength; i++ {
		token[i] = byte(random.Alphanumeric())
	}
	if token.CurrentlyExists() {
		token = newSession()
	}
	AllSessions = append(AllSessions, token)
	token.Expire()
	return token
}

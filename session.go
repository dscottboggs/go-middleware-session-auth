package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"time"
)

const (
	// 128 bits
	sessionKeyLength = 1 << 7
	// one week in seconds
	oneWeek = time.Second * 86400 * 7
	// the maximum number of bits that can fit in an uint8
	byteSizeConst = 1<<8 - 1
)

var (
	// the default amount of time until a token expires: 30 days
	expiryDelay = 24 * 30 * time.Hour
	// a big.Int representing the maximum number that can fit in an uint8
	byteSize = big.NewInt(byteSizeConst)
	// AllSessions stores each valid token
	AllSessions map[Session]*SessionMetadata
	// nullSession is found when the session doesn't exist
	nullSession Session
	// how frequently to sweep for expired tokens
	sweepDelay   time.Duration = 10 * time.Second
	sweeper                    = time.NewTicker(sweepDelay)
	sweepQuitter               = make(chan bool)
)

// The Session cookie store
type Session [sessionKeyLength]byte

type SessionMetadata struct {
	Expiry time.Time
}

func init() {
	AllSessions = make(map[Session]*SessionMetadata)
	go sweep()
}

// GetSession finds the token in AllSessions and returns the metadata
func (s *Session) GetMetadata() (sesh *SessionMetadata, found bool) {
	if (*s) == nullSession {
		return
	}
	sesh = AllSessions[*s]
	if sesh != nil && sesh.Expiry.Unix() > 0 {
		found = true
	}
	return
}

func (s *Session) CurrentlyExists() (found bool) {
	_, found = s.GetMetadata()
	return
}

// Delete the given token from the list of allowed sessions.
func (s *Session) Delete() {
	delete(AllSessions, *s)
}

func (s *Session) ExpireIn(duration time.Duration) error {
	sesh, ok := s.GetMetadata()
	if !ok {
		return fmt.Errorf("Session not found")
	}
	sesh.Expiry = time.Now().Add(duration)
	return nil
}

func (s *Session) ExpireAt(t time.Time) error {
	sesh, ok := s.GetMetadata()
	if !ok {
		return fmt.Errorf("Session not found")
	}
	sesh.Expiry = t
	return nil
}

func SetDefaultExpiry(t time.Duration) {
	expiryDelay = t
}

// NewSession returns a new random token.
func NewSession() (Session, *SessionMetadata) {
	var (
		token    Session
		temp     *big.Int
		err      error
		metadata = &SessionMetadata{
			Expiry: time.Now().Add(expiryDelay),
		}
	)
	for i := 0; i < sessionKeyLength; i++ {
		temp, err = rand.Int(rand.Reader, byteSize)
		if err != nil {
			log.Fatalf("error reading from random number generator! %v", err)
		}
		token[i] = byte(temp.Int64())
	}
	if token.CurrentlyExists() {
		token, metadata = NewSession()
	}
	AllSessions[token] = metadata
	return token, metadata
}

// SetCleanupInterval sets how frequently to sweep for expired tokens
func SetCleanupInterval(interval time.Duration) {
	sweeper.Stop()
	sweepQuitter <- true
	sweepDelay = interval
	sweeper = time.NewTicker(interval)
	go sweep()
}

// sweep the AllSessions object and clean up any expired sessions
func sweep() {
	for {
		select {
		case <-sweepQuitter:
			return
		case <-sweeper.C:
			doSweep()
		}
	}
}

func doSweep() {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		sweepDelay,
	)
	defer cancel()
	for sesh, metadata := range AllSessions {
		select {
		case <-ctx.Done():
			incrementSleepDelay()
			log.Printf(
				"WARNING took too long to sweep expired settings, raising "+
					"delay to %d seconds.",
				sweepDelay/time.Second,
			)
		default:
			if metadata.Expiry.Unix() < time.Now().Unix() {
				sesh.Delete()
			}
		}
	}
}

func incrementSleepDelay() {
	sweepDelay = sweepDelay * 15 / 10
}

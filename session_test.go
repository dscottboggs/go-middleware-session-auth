package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/dscottboggs/attest"
)

func BenchmarkNewSession(b *testing.B) {
	for index := 0; index < b.N; index++ {
		_, _ = NewSession()
	}
}
func BenchmarkHasSession(bench *testing.B) {
	// setup some sessions
	var (
		token Session
		round uint
	)
	for round = 1; round < 8; round++ {
		bench.Run(fmt.Sprintf("with %d users", 1<<round), func(b *testing.B) {
			for index := 0; index < 1<<round; index++ {
				// create variously sized maps to search
				token, _ = NewSession()
			}
			// reset the timer
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if !token.CurrentlyExists() {
					b.Fail()
				}
			}
		})
	}
}

func TestExpiry(t *testing.T) {
	SetCleanupInterval(500 * time.Millisecond)
	prechecks := func(
		test *attest.Test, token Session, metadata *SessionMetadata,
	) {
		test.DiffersByLessThan(
			int64(2),
			time.Now().Add(expiryDelay).Unix(),
			metadata.Expiry.Unix(),
		)
		if !token.CurrentlyExists() {
			test.Fatal("newly created session didn't exist")
		}
	}
	postchecks := func(
		test *attest.Test, token Session, metadata *SessionMetadata,
	) {
		if token.CurrentlyExists() {
			test.Error("token still existed after expiry time")
		}
		time.Sleep(1 * time.Second)
		if token.CurrentlyExists() {
			test.Error("token still existed another second later")
		}
		test.LessThan(time.Now().Unix(), metadata.Expiry.Unix())
	}
	t.Run("ExpireIn()", func(t *testing.T) {
		t.Run("valid session", func(t *testing.T) {

			test := attest.NewTest(t)
			token, metadata := NewSession()
			prechecks(&test, token, metadata)
			token.ExpireIn(1 * time.Second)
			time.Sleep(2500 * time.Millisecond)
			postchecks(&test, token, metadata)
		})
		t.Run("without valid session", func(t *testing.T) {
			test := attest.New(t)
			token, _ := NewSession()
			token.Delete()
			if token.CurrentlyExists() {
				t.Error("token existed after deletion")
			}
			test.NotNil(
				token.ExpireIn(1*time.Second),
				"got nil error from ExpireIn() on deleted token",
			)
		})
	})
	t.Run("ExpireAt()", func(t *testing.T) {
		t.Run("with valid session", func(t *testing.T) {

			test := attest.NewTest(t)
			token, metadata := NewSession()
			prechecks(&test, token, metadata)
			token.ExpireAt(time.Now().Add(1 * time.Second))
			time.Sleep(2500 * time.Millisecond)
			postchecks(&test, token, metadata)
		})
		t.Run("without valid session", func(t *testing.T) {
			test := attest.New(t)
			token, _ := NewSession()
			token.Delete()
			if token.CurrentlyExists() {
				t.Error("token existed after deletion")
			}
			test.NotNil(
				token.ExpireAt(time.Now().Add(1*time.Second)),
				"got nil error from ExpireIn() on deleted token",
			)
		})
	})
}
func TestDeletion(t *testing.T) {
	test := attest.New(t)
	token, metadata := NewSession()
	test.DiffersByLessThan(
		int64(2),
		time.Now().Add(expiryDelay).Unix(),
		metadata.Expiry.Unix(),
	)
	if !token.CurrentlyExists() {
		t.Errorf("token doesn't exist")
	}
	token.Delete()
	if token.CurrentlyExists() {
		t.Errorf("token exists")
	}
}

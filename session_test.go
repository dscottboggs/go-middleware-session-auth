package auth

import (
	"fmt"
	"testing"

	"github.com/dscottboggs/attest"
)

func TestHasSession(t *testing.T) {
	test := attest.New(t)
	token, err := NewSession()
	test.Handle(err)
	test.Logf("Token: %#+v", token)
	if !HasSession(token) {
		test.Error("does not have session from NewToken")
	}
}
func TestDoesNotHaveSession(t *testing.T) {
	test := attest.New(t)
	token, err := newSession()
	test.Handle(err)
	if hasSession(token) {
		test.Error("has session from newToken.")
	}
	if hasSession(nullSession) {
		test.Error("has null session")
	}
}
func BenchmarkNewSession(b *testing.B) {
	var err error
	for index := 0; index < b.N; index++ {
		_, err = newSession()
		if err != nil {
			b.Error(err)
		}
	}
}
func BenchmarkHasSession(bench *testing.B) {
	// setup some sessions
	var (
		token string
		err   error
		round uint
	)
	for round = 1; round < 8; round++ {
		bench.Run(fmt.Sprintf("with %d users", 1<<round), func(b *testing.B) {
			for index := 0; index < 1<<round; index++ {
				token, err = NewSession()
				if err != nil {
					b.Error(err)
				}
			}
			// reset the timer
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if !HasSession(token) {
					b.Fail()
				}
			}
		})
	}
}

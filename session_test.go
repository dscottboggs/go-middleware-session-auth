package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/dscottboggs/attest"
)

func TestHasSession(t *testing.T) {
	test := attest.New(t)
	token := NewSession()
	test.Logf("Token: %#+\n", token)
	if !HasSession(token) {
		test.Error("does not have session from NewToken")
	}
}
func BenchmarkNewSession(b *testing.B) {
	for index := 0; index < b.N; index++ {
		_ = newSession()
	}
}
func BenchmarkHasSession(bench *testing.B) {
	// setup some sessions
	var (
		token string
		round uint
	)
	for round = 1; round < 8; round++ {
		bench.Run(fmt.Sprintf("with %d users", 1<<round), func(b *testing.B) {
			for index := 0; index < 1<<round; index++ {
				token = NewSession()
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

func TestExpiryAndDeletion(t *testing.T) {
	test := attest.NewTest(t)
	token := newSession()
	if !token.CurrentlyExists() {
		test.Fatal("newly created session didn't exist")
	}
	token.ExpireIn(2 * time.Second)
	time.Sleep(2500 * time.Millisecond)
	if token.CurrentlyExists() {
		test.Error("token still existed after expiry time")
	}
	time.Sleep(1 * time.Second)
	if token.CurrentlyExists() {
		test.Error("token still existed another second later")
	}
	token = newSession()
	if !token.CurrentlyExists() {
		test.Fatal("newly created session didn't exist")
	}
	token.Delete()
	if token.CurrentlyExists() {
		test.Error("token still exists after deletion")
	}
	tokenString := NewSession()
	if !HasSession(tokenString) {
		test.Fatal("newly created session didn't exist")
	}
	Delete(tokenString)
	if HasSession(tokenString) {
		test.Error("token still exists after deletion")
	}
	if nullSession.CurrentlyExists() {
		test.Error("null session is authenticated!")
	}
}

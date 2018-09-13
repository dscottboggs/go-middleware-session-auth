package auth

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

/*
Type definitions:
*/

type salt [SaltSize]byte

func (s *salt) Randomize() (err error) {
	(*s), err = RandomSalt()
	return
}

// Token -- the stored token and corresponding salt of a given user
type Token struct {
	HashValue [KeyLength]byte
	Salt      salt
}

// NewAuthToken from the given secret. Handles creating the random salt and
// hashing the value.
func NewAuthToken(secret []byte) (t Token, err error) {
	err = t.Salt.Randomize()
	if err != nil {
		return
	}
	hashval := pbkdf2.Key(
		secret, t.Salt[:], Iterations, KeyLength, sha512.New,
	)
	copy(t.HashValue[:], hashval)
	return
}

// The Username of a user
type Username string

// ChangePassword for a given user from the old password to the new one, if the
// old one is correct.
// returns non-nil error on failure to authenticate user, failure to create a
// salt, or the result of SyncAllUsers, which may be a non-nil error.
func (u *Username) ChangePassword(from, to string) error {
	if !u.IsAuthenticatedBy(from) {
		return fmt.Errorf("Password %s doesn't authenticate %v", from, u)
	}
	token, err := NewAuthToken([]byte(to))
	if err != nil {
		return err
	}
	AllUsers[*u] = &token
	return SyncAllUsers()
}

// Delete the given user if the given password is correct.
// Returns a typed error on failure, which would satisfy IsNoSuchUser() or
// IsWrongPassword()
func (u *Username) Delete(password string) error {
	if AllUsers[*u] == nil {
		return NoSuchUser(u)
	}
	if u.IsAuthenticatedBy(password) {
		AllUsers[*u] = nil
	} else {
		return WrongPassword(u)
	}
	return nil
}

// IsAuthenticatedBy --
// Checks if a user IsAuthenticatedBy a password or not.
func (u *Username) IsAuthenticatedBy(password string) bool {
	user := AllUsers[*u]
	if user == nil {
		return false
	}
	return string(pbkdf2.Key(
		[]byte(password),
		user.Salt[:],
		Iterations,
		KeyLength,
		sha512.New,
	)) == string(user.HashValue[:])
}

// RandomSalt creates a cryptographically random AuthToken.Salt value.
func RandomSalt() ([SaltSize]byte, error) {
	var salt [SaltSize]byte
	for index := range salt {
		newval, err := rand.Int(rand.Reader, big.NewInt(2<<7-1))
		if err != nil {
			return salt, err
		}
		if byteval := newval.Int64(); newval.IsUint64() && byteval < 255 {
			salt[index] = byte(byteval)
		} else {
			return salt, fmt.Errorf(
				"newval %d overflowed byte at index %d",
				newval,
				index,
			)
		}
	}
	return salt, nil
}

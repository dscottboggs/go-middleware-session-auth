package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/sha512"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	random "github.com/dscottboggs/go-random-string"
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

// UserCollection -- A collection of users and their associated tokens
type UserCollection map[Username]*Token

// Write the UserCollection to the given Writer and close it.
func (c *UserCollection) Write(to io.WriteCloser) error {
	defer func() { to.Close() }()
	return c.WriteWithoutClose(to)
}

// WriteWithoutClose -- Write the collection to the given destination which may
// or may not implement Close().
func (c *UserCollection) WriteWithoutClose(destination io.Writer) error {
	encoder := gob.NewEncoder(destination)
	return encoder.Encode(c)
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

/*
^^^ End type definitions

Global variables:
*/

// AllUsers -- The map of all Usernames to their AuthTokens
var AllUsers UserCollection

/*
^^^ End global variables

Code:
*/

// Read a gob-encoded reader into a UserCollection, or return an error on
// failure.
func Read(config io.Reader) (UserCollection, error) {
	users := make(UserCollection, 0)
	decoder := gob.NewDecoder(config)
	err := decoder.Decode(&users)
	return users, err
}

// ReadFrom a given filepath, just like Read.
func ReadFrom(config string) (UserCollection, error) {
	configFile, err := os.Open(config)
	if err != nil {
		return UserCollection{}, err
	}
	return Read(configFile)
}

// SyncAllUsers to the file.
func SyncAllUsers() error {
	// create the file
	configFile, err := os.Create(ConfigLocation)
	// return any error gotten from the file creation, unless it's just that
	// the file exists already; we're overwriting it anyway.
	if err != nil && !(os.IsExist(err) || os.IsNotExist(err)) {
		return err
	}
	// write the config
	err = AllUsers.Write(configFile)
	// return if any errors encounterd
	if err != nil {
		return fmt.Errorf(
			"Error writing config file (%s): %v",
			ConfigLocation,
			err,
		)
	}
	// confirm written values
	read, err := ReadFrom(ConfigLocation)
	if err != nil {
		return err
	}
	for k, v := range read {
		mv := AllUsers[k]
		// check token
		for index, byteval := range v.HashValue {
			if mv.HashValue[index] != byteval {
				return fmt.Errorf(
					"Mismatched tokens %v and %v",
					v,
					mv,
				)
			}
		}
	}
	// success return nil
	return nil
}

// PromptForSingleUser --
// Create an interactive prompt to create the first user. Requires a valid TTY.
func PromptForSingleUser() error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Admin username: [admin]")
	uname, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	uname = strings.Trim(uname, whitespace)
	if len(uname) == 0 {
		uname = "admin"
	}
	if (strings.Index(uname, ColSeparator) != -1) || (strings.Index(uname, LineSeparator) != -1) {
		return fmt.Errorf(
			"Username cannot contain '%s' or '%s'",
			ColSeparator,
			LineSeparator,
		)
	}
	fmt.Print("Admin password: [leave blank to auto-generate]")
	pass, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	pass = strings.Trim(pass, whitespace)
	if pass == "" {
		pass, err = random.Words(3, "_")
		if err != nil {
			return fmt.Errorf("error generating password: %v", err)
		}
	}
	fmt.Printf("Using username %s and password %s.", uname, pass)
	return CreateNewUser(uname, pass)
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

// CreateNewUser with the given information
func CreateNewUser(name, password string) error {
	if AllUsers[Username(name)] != nil {
		return UserExists(name)
	}
	token, err := NewAuthToken([]byte(password))
	if err != nil {
		return err
	}
	AllUsers[Username(name)] = &token
	return SyncAllUsers()
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

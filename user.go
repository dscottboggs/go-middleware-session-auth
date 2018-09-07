package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	random "github.com/dscottboggs/go-random-string"
	"golang.org/x/crypto/pbkdf2"
)

// AuthToken -- the stored token and corresponding salt of a given user
type AuthToken struct {
	Token []byte
	Salt  []byte
}

// A User's usename
type User string

func (u *User) ChangePassword(from, to string) error {
	if !u.IsAuthenticatedBy(from) {
		return fmt.Errorf("Password %s doesn't authenticate %v", from, u)
	}
	salt, err := RandomSalt()
	if err != nil {
		return err
	}
	tokenValue := pbkdf2.Key(
		[]byte(to), salt[:], Iterations, KeyLength, sha512.New)
	token := AuthToken{Token: tokenValue, Salt: salt[:]}
	AllUsers[*u] = &token
	return SyncAllUsers()
}

func (user *User) Delete(password string) error {
	if AllUsers[*user] == nil {
		return NoSuchUser(user)
	}
	if user.IsAuthenticatedBy(password) {
		AllUsers[*user] = nil
	} else {
		return WrongPassword(user)
	}
	return nil
}

var AllUsers map[User]*AuthToken

// Sync all users to the file.
func SyncAllUsers() error {
	// create the file
	configFile, err := os.Create(ConfigLocation)
	defer func() {
		if err := configFile.Close(); err != nil {
			log.Printf("error closing %s: %v", ConfigLocation, err)
		}
	}()
	// return any error gotten from the file creation, unless it's just that
	// the file exists already; we're overwriting it anyway.
	if err != nil && !(os.IsExist(err) || os.IsNotExist(err)) {
		return err
	}
	// write the config
	configString := ToString(AllUsers)
	written, err := configFile.WriteString(configString)
	// return if any errors encounterd
	if charsToWrite := len(configString); err != nil || written != charsToWrite {
		return fmt.Errorf(
			"Error writing config file (%v) and/or mismatch in characters "+
				"written (%d) versus length of string to be written (%d).",
			ConfigLocation,
			written,
			charsToWrite,
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
		for index, byteval := range v.Token {
			if mv.Token[index] != byteval {
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

// ToString pickles the data structure into a string, ready to be written by
// SyncAllUsers(), and read by FromStringToValues()
func ToString(values map[User]*AuthToken) string {
	var strVersion string
	for k, v := range values {
		if v != nil {
			strVersion +=
				string(k) +
					ColSeparator +
					hex.EncodeToString(v.Salt[:]) +
					ColSeparator +
					hex.EncodeToString(v.Token[:]) +
					"\n"
		}
	}
	return strVersion
}

// FromStringToValues converts the string which has just been read into the
// appropriate data structure. It returns an error if it encounters duplicate
// users.
func FromStringToValues(str string) (map[User]*AuthToken, error) {
	var out = make(map[User]*AuthToken)
	for _, line := range strings.Split(str, LineSeparator) {
		thisLineVals := strings.Split(line, ColSeparator)
		if len(thisLineVals) != 3 {
			if len(line) == 0 {
				continue
			}
			return out, fmt.Errorf(
				"Got invalid line %s when trying to parse %s",
				line,
				str,
			)
		}
		uName := User(thisLineVals[0])
		salt, err := hex.DecodeString(thisLineVals[1])
		if err != nil {
			return out, err
		}
		token, err := hex.DecodeString(thisLineVals[2])
		if err != nil {
			return out, err
		}
		auth := AuthToken{Salt: salt, Token: token}
		if out[uName] != nil {
			return out, UserExists(string(uName))
		}
		out[uName] = &auth
	}
	return out, nil
}

func PromptForSingleUser() error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Admin username: [admin]")
	uname, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	uname = strings.Trim(uname, WHITESPACE)
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
	pass = strings.Trim(pass, WHITESPACE)
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
func (u *User) IsAuthenticatedBy(password string) bool {
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
	)) == string(user.Token[:])
}

// CreateNewUser with the given information
func CreateNewUser(name, password string) error {
	if AllUsers[User(name)] != nil {
		return UserExists(name)
	}
	salt, err := RandomSalt()
	if err != nil {
		return err
	}
	tokenValue := pbkdf2.Key(
		[]byte(password),
		salt[:],
		Iterations,
		KeyLength,
		sha512.New,
	)
	token := AuthToken{
		Token: tokenValue,
		Salt:  salt[:],
	}
	AllUsers[User(name)] = &token
	return SyncAllUsers()
}

// RandomSalt randomizes the given AuthToken.Salt value
func RandomSalt() ([SaltSize]byte, error) {
	var salt [SaltSize]byte
	for index := range salt {
		newval, err := rand.Int(rand.Reader, big.NewInt(2<<7-1))
		if err != nil {
			return salt, err
		}
		if newval.IsUint64() && newval.Int64() < 255 {
			salt[index] = byte(newval.Int64())
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

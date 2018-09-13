package auth

import (
	"encoding/gob"
	"fmt"
	"io"
	"os"
)

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

// AllUsers -- The map of all Usernames to their AuthTokens
var AllUsers UserCollection

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

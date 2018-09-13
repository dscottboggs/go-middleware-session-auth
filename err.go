package auth

import "fmt"

type userExistsError struct{ error }

// UserExists returns an error that satisfies IsUserExists
func UserExists(name string) error {
	return userExistsError{
		fmt.Errorf(
			"%s already exists, use ChangePasswordFor, not CreateNewUser",
			name,
		),
	}
}

// IsUserExists returns true if an error was created by calling UserExists()
func IsUserExists(err error) bool {
	return fmt.Sprintf("%T", err) == "auth.userExistsError"
}

type wrongPasswordError struct{ error }

// WrongPassword returns an error that satisfies IsWrongPassword()
func WrongPassword(user *Username) error {
	return wrongPasswordError{
		fmt.Errorf(
			"user %v was not able to be authenticated by the given password",
			user,
		),
	}
}

// IsWrongPassword returns true if an error was created by calling WrongPassword()
func IsWrongPassword(err error) bool {
	return fmt.Sprintf("%T", err) == "auth.wrongPasswordError"
}

type noSuchUser struct{ error }

// NoSuchUser returns an error that satisfies IsNoSuchUser()
func NoSuchUser(user *Username) error {
	return noSuchUser{
		fmt.Errorf(
			"user %v does not exist",
			user,
		),
	}
}

// IsNoSuchUser returns true if an error was created by calling NoSuchUser()
func IsNoSuchUser(err error) bool {
	return fmt.Sprintf("%T", err) == "auth.wrongPasswordError"
}

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

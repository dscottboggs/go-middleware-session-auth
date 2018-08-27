package auth

import (
	"encoding/hex"
	"testing"

	"github.com/dscottboggs/attest"
)

func TestAuthentication(t *testing.T) {
	test := attest.Test{t}
	username := User("test authentication user's name")
	testpass := "test authentication user's password. such strong. much protect."
	test.Handle(CreateNewUser(string(username), testpass))
	if !username.IsAuthenticatedBy(testpass) {
		t.Error("Authentication failed.")
	}
	if username.IsAuthenticatedBy("password") {
		t.Error("Authentication was granted for incorrect password.")
	}
	if user := User("nonexistent user"); user.IsAuthenticatedBy("password") {
		t.Error("nonexistent user was authenticated")
	}
}

func TestToAndFromString(t *testing.T) {
	test := attest.Test{t}
	testvals := make(map[User]*AuthToken)
	username := User("test to-and-from-string user's name")
	testpass := "test to-and-from-string user's password. such strong. much protect."
	test.Handle(CreateNewUser(string(username), testpass))
	if !username.IsAuthenticatedBy(testpass) {
		t.Error("Authentication failed.")
	}
	if username.IsAuthenticatedBy("password") {
		t.Error("Authentication was granted for incorrect password.")
	}
	testvals[username] = AllUsers[username]
	auth := testvals[username]
	test.Logf(
		"Token: %v\nSalt: %v",
		hex.EncodeToString(auth.Token),
		hex.EncodeToString(auth.Salt))
	expectedStr := string(username) +
		ColSeparator +
		hex.EncodeToString(auth.Salt) +
		ColSeparator +
		hex.EncodeToString(auth.Token) +
		LineSeparator
	test.Equals(expectedStr, ToString(testvals))
	fromStr, err := FromStringToValues(expectedStr)
	test.Handle(err)
	test.NotNil(fromStr[username], "fromStr[username] was nil")
	for index, byteval := range auth.Salt {
		test.Equals(byteval, fromStr[username].Salt[index])
	}
	for index, byteval := range auth.Token {
		test.Equals(byteval, fromStr[username].Token[index])
	}
	// Failure cases
	_, err = FromStringToValues("invalid string")
	test.NotNil(err, "got nil error for invalid string to FromStringToValues")
	_, err = FromStringToValues(
		string(username) +
			ColSeparator +
			string(auth.Salt) +
			ColSeparator +
			hex.EncodeToString(auth.Token))
	test.NotNil(
		err,
		"got nil error when passing malformed string to FromStringToValues",
	)
	_, err = FromStringToValues(
		string(username) +
			ColSeparator +
			hex.EncodeToString(auth.Salt) +
			ColSeparator +
			string(auth.Token))
	test.NotNil(
		err,
		"got nil error when passing malformed string to FromStringToValues",
	)
	_, err = FromStringToValues(
		string(username) +
			ColSeparator +
			hex.EncodeToString(auth.Salt) +
			ColSeparator +
			hex.EncodeToString(auth.Token) +
			LineSeparator +
			string(username) +
			ColSeparator +
			hex.EncodeToString(auth.Salt) +
			ColSeparator +
			hex.EncodeToString(auth.Token))
	test.NotNil(
		err,
		"got nil error when passing malformed string to FromStringToValues",
	)
}

func TestChangePassword(t *testing.T) {
	test := attest.Test{t}
	username := User("test change password user's name")
	testpass := "test change password user's password"
	test.Handle(CreateNewUser(string(username), testpass))
	if !username.IsAuthenticatedBy(testpass) {
		t.Error("auth failed before changing password.")
	}
	testchpw := "test change password user's new password"
	if username.IsAuthenticatedBy(testchpw) {
		t.Error("user was authenticated by new password before changing.")
	}
	test.Handle(username.ChangePassword(testpass, testchpw))
	if !username.IsAuthenticatedBy(testchpw) {
		t.Error("authentication failed after changing password")
	}
	if username.IsAuthenticatedBy(testpass) {
		t.Error("user was still authenticated by old password")
	}
	if err := CreateNewUser(string(username), testpass); !IsUserExists(err) {
		t.Errorf(
			"Error received from CreateNewUser() was not a UserExists error, "+
				"it was:\n%T; %v",
			err,
			err)
	}
	test.NotNil(
		username.ChangePassword("invalid", "irrellevant"),
		"got nil error when trying to change password by passing invalid "+
			"password",
	)
}

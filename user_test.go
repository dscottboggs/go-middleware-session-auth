package auth

import (
	"crypto/sha512"
	"io"
	"testing"

	"github.com/dscottboggs/attest"
	"golang.org/x/crypto/pbkdf2"
)

func TestAuthentication(t *testing.T) {
	test := attest.New(t)
	AllUsers = make(UserCollection)
	username := Username("test authentication user's name")
	testpass := "test authentication user's password. such strong. much protect."
	test.Handle(CreateNewUser(string(username), testpass))
	if !username.IsAuthenticatedBy(testpass) {
		t.Error("Authentication failed.")
	}
	if username.IsAuthenticatedBy("password") {
		t.Error("Authentication was granted for incorrect password.")
	}
	if user := Username("nonexistent user"); user.IsAuthenticatedBy("password") {
		t.Error("nonexistent user was authenticated")
	}
}

func TestChangePassword(t *testing.T) {
	test := attest.Test{t}
	username := Username("test change password user's name")
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

func TestReadAndWrite(t *testing.T) {
	const (
		username = "test r/w user"
		password = "test rw/ user's password"
	)
	var (
		test    = attest.New(t)
		out, in = io.Pipe()
		user    = Username(username)
		readkey [KeyLength]byte
	)
	AllUsers = make(UserCollection)
	test.Handle(CreateNewUser(username, password))
	test.Attest(user.IsAuthenticatedBy(password), "user failed authentication")
	test.Equals(1, len(AllUsers))
	go func() { test.Handle(AllUsers.Write(in)) }()
	read := test.EatError(Read(out)).(UserCollection)
	test.Equals(1, len(read))
	copy(
		readkey[:],
		pbkdf2.Key(
			[]byte(password), read[user].Salt[:], Iterations, KeyLength, sha512.New,
		),
	)
	test.Equals(
		len(AllUsers[user].HashValue),
		len(readkey),
		"key lengths differed -- orig: %d; read: %d",
		len(AllUsers[user].HashValue),
		len(readkey),
	)
	for index, byteval := range AllUsers[user].HashValue {
		test.Equals(
			byteval,        //expected
			readkey[index], // actual
			// message:
			"read key didn't match original token at index %d\norig: %d\nread: %d",
			index,
			byteval,
			readkey[index],
		)
	}
}

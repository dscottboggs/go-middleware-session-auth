package main

import (
	"flag"
	"log"
	"os"

	"github.com/dscottboggs/go-middleware-session-auth"
)

const (
	actionCreate = iota
	actionCheck
	actionDelete
	actionUpdate
	statusOK             = 0
	statusIncorrectUsage = 64
)

func main() {
	var (
		tokenLocation string
		actionString  string
		uname         string
		pw            string
		newpw         string
	)
	flag.StringVar(
		&actionString,
		"do",
		"check",
		"action to be taken: new,create,check,verify,delete,update,change,up,c,v,u,d",
	)
	flag.StringVar(&tokenLocation, "tf", "", "the token file to use")
	flag.StringVar(&uname, "usr", "", "the username to work with")
	flag.StringVar(&pw, "pw", "", "the password to work with")
	flag.StringVar(&newpw, "new-pw", "", "the new password to use when changing.")

	flag.Parse()

	var foundEmptyString bool
	switch {
	case tokenLocation == "":
		log.Printf("tokenLocation: %s\n", tokenLocation)
		foundEmptyString = true
		fallthrough
	case uname == "":
		log.Printf("uname: %s\n", uname)
		foundEmptyString = true
		fallthrough
	case pw == "":
		log.Printf(" pw: %s\n", pw)
		foundEmptyString = true
	}
	if foundEmptyString {
		flag.Usage()
		os.Exit(statusIncorrectUsage)
	}
	err := auth.Initialize(tokenLocation)
	if err != nil {
		log.Fatal(err)
	}
	switch actionString {
	case "new", "create", "c", "add":
		if err := auth.CreateNewUser(uname, pw); err != nil {
			log.Fatalf("failed to create new user: %v\n", err)
		}
		os.Exit(statusOK)
	case "check", "verify", "v":
		if user := auth.Username(uname); user.IsAuthenticatedBy(pw) {
			log.Println("OK")
			os.Exit(statusOK)
		}
		log.Println("NOT OK")
		os.Exit(1)
	case "delete", "d":
		user := auth.Username(uname)
		if err := user.Delete(pw); err != nil {
			log.Fatalf("couldn't delete user %s; %v\n", uname, err)
		}
		os.Exit(statusOK)
	case "update", "change", "u", "up", "upd8":
		user := auth.Username(uname)
		if newpw == "" {
			log.Println("no new password specified.")
			flag.PrintDefaults()
			os.Exit(statusIncorrectUsage)
		}
		if err := user.ChangePassword(pw, newpw); err != nil {
			log.Fatalf("couldn't change password for %s; %v\n", uname, err)
		}
		os.Exit(0)
	default:
		log.Fatalf("invalid action %s\n", actionString)
	}

}

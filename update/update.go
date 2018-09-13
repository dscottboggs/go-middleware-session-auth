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

	for _, flagstr := range []string{tokenLocation, uname, pw} {
		if flagstr == "" {
			flag.PrintDefaults()
			os.Exit(statusIncorrectUsage)
		}
	}

	switch actionString {
	case "new", "create", "c":
		if err := auth.CreateNewUser(uname, pw); err != nil {
			log.Fatalf("failed to create new user: %v", err)
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
			log.Fatalf("couldn't delete user %s; %v", uname, err)
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
			log.Fatalf("couldn't change password for %s; %v", uname, err)
		}
		os.Exit(0)
	default:
		log.Fatalf("invalid action %s", actionString)
	}

}

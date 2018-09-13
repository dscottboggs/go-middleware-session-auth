package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	random "github.com/dscottboggs/go-random-string"
)

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

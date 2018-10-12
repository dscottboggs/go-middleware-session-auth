package auth

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
)

// package constants
const (
	// Iterations -- the number of times to hash the password
	Iterations = 2 << 13
	// KeyLength -- the length of the token to store.
	KeyLength = 2 << 5
	// SaltSize -- the number of bytes of salt entropy to include
	SaltSize = 2 << 4
	// LineSeparator separates the lines when dumping or reading from the
	// string format. The separator substrings are completely arbitrary, the
	// only requirement for Line/ColSeparator characters is
	// =~ /[\dabcdef$]*/
	// that is, it must not be any of: numeric digits, the letters A through F,
	// or the $ symbol. Anything else is fair game.
	LineSeparator = "\n"
	// ColSeparator separates the columns when dumping or reading from the
	// string format
	ColSeparator = "-|-"
	eof          = 0
	whitespace   = "\n\t \x00"
	// wordListURL is where to download the list of words to choose from
	wordListURL = "http://svnweb.freebsd.org/csrg/share/dict/words" +
		"?view=co&content-type=text/plain"
)

// ConfigLocation is where the usernames and (encrypted) passwords are stored
var ConfigLocation string

// wordListLocation is where the word list should be stored
var wordListLocation string

var unauthenticated []*regexp.Regexp

// IsUnauthenticatedEndpoint compares the given route to each of the
// permissively-configured endpoints. If an enpdoint matches one of these
// expressions, it will be allowed regardless of the BasicAuth header.
func IsUnauthenticatedEndpoint(route string) bool {
	for _, uRte := range unauthenticated {
		if uRte.MatchString(route) {
			return true
		}
	}
	return false
}

func init() {
	AllUsers = make(map[Username]*Token)
	wordListLocation = path.Join(ConfigLocation, "..", "wordlist.txt")
	config_location_file := os.Getenv("go_middleware_session_keys_file")
	if config_location_file != "" {
		cfg_loc_bytes, err := ioutil.ReadFile(config_location_file)
		if err != nil {
			log.Fatalf(
				"go_middleware_session_keys_file environment variable "+
					`specified (as "%s"), but error "%v" when trying to read it`,
				config_location_file,
				err,
			)
		}
		ConfigLocation = strings.TrimSpace(string(cfg_loc_bytes))
		return
	}
	ConfigLocation := os.Getenv("go_middleware_session_keys")
	if ConfigLocation == "" {
		ConfigLocation = path.Join(
			configDir(),
			"auth.tokens",
		)
	}
}

func configDir() string {
	configDirectory := os.Getenv("XGD_CONFIG_HOME")
	if configDirectory != "" {
		return configDirectory
	}
	homedir := os.Getenv("HOME")
	if homedir == "" {
		log.Fatal("Couldn't find home directory!")
	}
	return path.Join(
		homedir,
		".config",
		"go-middleware-session-auth",
	)
}

// FirstRun Initializes the global varirables, creates a new user, then syncs
// For non-interactive initializing when there isn't an existing user.
func FirstRun(
	username, password, config string,
	unauthenticatedEndpoints ...string,
) error {
	if err := globals(config, unauthenticatedEndpoints...); err != nil {
		return err
	}
	if err := setupFile(config); err != nil {
		if err := CreateNewUser(username, password); err != nil {
			return err
		}
		return setupFile(config)
	}
	return nil
}

func globals(config string, unauthenticatedEndpoints ...string) error {
	ConfigLocation = config
	for _, endpoint := range unauthenticatedEndpoints {
		exp, err := regexp.Compile("^" + endpoint)
		if err != nil {
			return fmt.Errorf(
				"Error parsing regular expression /%s/: %v",
				endpoint,
				err,
			)
		}
		unauthenticated = append(unauthenticated, exp)
	}
	return nil
}

func setupFile(config string) error {
	info, err := os.Stat(ConfigLocation)
	if os.IsExist(err) || (err == nil && info.Size() > 0) {
		AllUsers, err = ReadFrom(config)
		if err != nil {
			return err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(AllUsers) < 1 {
		if err = PromptForSingleUser(); err != nil {
			return err
		}
	}
	if err = SyncAllUsers(); err != nil {
		return err
	}
	readValues, err := ReadFrom(config)
	if err != nil {
		return err
	}
	for k, v := range AllUsers {
		if AllUsers[k] != v {
			return fmt.Errorf(
				"got mismatch after write:\n%#+v\n%#+v\nAT %s: %#+v != %#+v",
				AllUsers,
				readValues,
				k,
				readValues[k],
				v,
			)
		}
	}
	return nil
}

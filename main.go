package auth

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
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
	WHITESPACE   = "\n\t "
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
	AllUsers = make(map[User]*AuthToken)
	wordListLocation = path.Join(ConfigLocation, "..", "wordlist.txt")
}

/* Initialize global variables
 *
 * @param config [string]: the location where the authentication tokens should
 *		be stored, e.g. ~/.config/appname/auth.tokens
 * @param unauthenticatedEndpoints [strings]: the remaining arguments are
 *		regular expressions to be matched against for permissive endpoints.
 *		These endpoints will be allowed through the BasicAuth handler regardless
 *		of their actual basic authentication headers. This allows for, for
 *		example, an unauthenticated login page or some scripts to load
 *		regardless of authentication. The expression is concatenated with the
 *		character '^', making it only match the beginning of the route path.
 */
func Initialize(config string, unauthenticatedEndpoints ...string) error {
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

func ReadFrom(config string) (map[User]*AuthToken, error) {
	txt, err := ioutil.ReadFile(config)
	if err != nil {
		return map[User]*AuthToken{}, err
	}
	text := string(txt)
	return FromStringToValues(text)
}

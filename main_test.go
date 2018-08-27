package auth

import (
	"log"
	"os"
	"path"
	"testing"
)

func TestMain(m *testing.M) {
	var testdir = createTestDir()
	ConfigLocation = path.Join(testdir, "auth.tokens")
	os.Exit(m.Run())
}

func createTestDir() string {
	testdir := path.Join(os.TempDir(), "middlware-basicauth-test")
	info, statErr := os.Stat(testdir)
	if os.IsNotExist(statErr) {
		mkdirErr := os.Mkdir(testdir, os.ModeDir|os.FileMode(0755))
		if os.IsPermission(mkdirErr) {
			log.Fatalf("Can't create %s, no permissions", testdir)
		} else if mkdirErr != nil {
			log.Fatal(mkdirErr)
		}
		info, statErr = os.Stat(testdir)
	}
	if statErr != nil {
		log.Fatal(statErr)
	}
	if info.IsDir() {
		return testdir
	} else {
		log.Fatalf("%s isn't a directory!", testdir)
	}
	return ""
}

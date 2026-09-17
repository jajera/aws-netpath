package cli

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// The release build stamps the version by symbol path, which the compiler does
// not check: -X against a variable that no longer exists is silently ignored and
// the binary ships reporting "dev". These tests pin the two ends of that link so
// moving this package, or renaming Version, fails here rather than in a release.

func TestVersionDefaultsToDev(t *testing.T) {
	// An unstamped build has to look unstamped. Any other default would let a
	// local build present itself as a release.
	if Version != "dev" {
		t.Errorf("Version is %q in an unstamped build, want %q", Version, "dev")
	}
}

func TestReleaseScriptStampsThisPackage(t *testing.T) {
	script, err := os.ReadFile("../../scripts/release.sh")
	if err != nil {
		t.Fatalf("read the release script: %v", err)
	}

	// PkgPath is resolved by the compiler, so it tracks the package wherever it
	// moves; the script's literal does not.
	want := reflect.TypeOf(command{}).PkgPath() + ".Version"
	if !strings.Contains(string(script), want) {
		t.Errorf("scripts/release.sh does not stamp %s, so a release build would report %q", want, Version)
	}
}

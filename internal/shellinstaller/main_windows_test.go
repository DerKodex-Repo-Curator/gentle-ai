//go:build windows

package shellinstaller

import (
	"fmt"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Gentle Shell refuses elevated terminals, so its Windows checks require
// selections owned by the current user. An elevated process (the GitHub
// Windows runner) creates objects owned by BUILTIN\Administrators instead, so
// the tests make this process create objects owned by its user SID, as an
// unelevated account would. Product code is unchanged.
func TestMain(m *testing.M) {
	if err := ownNewObjectsByProcessUser(); err != nil {
		fmt.Fprintf(os.Stderr, "shellinstaller tests: cannot own new objects by the process user: %v\n", err)
	}
	os.Exit(m.Run())
}

func ownNewObjectsByProcessUser() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		return err
	}
	defer token.Close()
	if !token.IsElevated() {
		return nil
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	owner := struct{ Owner *windows.SID }{Owner: user.User.Sid} // TOKEN_OWNER
	return windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner)))
}

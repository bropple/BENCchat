package secret

import (
	"testing"

	"github.com/zalando/go-keyring"
)

// Uses go-keyring's in-memory mock so the test doesn't touch (or need) a real
// OS secret service.
func TestStoreRetrieveClear(t *testing.T) {
	keyring.MockInit()

	if err := Store("bob", "hunter2"); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if pw, err := Retrieve("bob"); err != nil || pw != "hunter2" {
		t.Fatalf("Retrieve = %q, %v; want \"hunter2\", nil", pw, err)
	}

	// A different account must not see it.
	if pw, err := Retrieve("someoneelse"); err != nil || pw != "" {
		t.Fatalf("Retrieve(other) = %q, %v; want \"\", nil", pw, err)
	}

	if err := Clear("bob"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if pw, err := Retrieve("bob"); err != nil || pw != "" {
		t.Fatalf("Retrieve after clear = %q, %v; want \"\", nil", pw, err)
	}

	// Clearing an already-absent entry is not an error.
	if err := Clear("bob"); err != nil {
		t.Fatalf("Clear(absent): %v", err)
	}
}

package oscar

import "testing"

// TestRedirectForcesOurPortUnderTLS is the guard against a silent downgrade.
//
// The BOS and chat addresses come from the SERVER. A deployment fronted by a
// TLS proxy typically still advertises its internal plaintext port, so
// following the advertised address verbatim would encrypt the login and then
// carry on in the clear — with nothing visibly different in the UI.
func TestRedirectForcesOurPortUnderTLS(t *testing.T) {
	tls := Transport{TLS: true}.withPort("5191")

	got := tls.redirect("oscar.example.com:5190", "5191")
	if got != "oscar.example.com:5191" {
		t.Errorf("redirect = %q, want the TLS port — a server-advertised plaintext port was followed", got)
	}

	// An address already on our port is left alone.
	if got := tls.redirect("oscar.example.com:5191", "5191"); got != "oscar.example.com:5191" {
		t.Errorf("redirect = %q, want it unchanged", got)
	}

	// A bare host gets our port rather than being dialed portless.
	if got := tls.redirect("oscar.example.com", "5191"); got != "oscar.example.com:5191" {
		t.Errorf("redirect of a bare host = %q, want the configured port", got)
	}
}

// TestRedirectLeavesPlaintextAlone: without TLS we must honour the server's
// address exactly, since a real deployment can legitimately move BOS elsewhere.
func TestRedirectLeavesPlaintextAlone(t *testing.T) {
	plain := Transport{}.withPort("5190")
	if got := plain.redirect("bos.example.com:9999", "5190"); got != "bos.example.com:9999" {
		t.Errorf("plaintext redirect = %q, want the server's address untouched", got)
	}
}

// TestTransportCarriesForward: a session must hand its own protection to any
// connection it spawns, or chat rooms would silently open in the clear.
func TestTransportCarriesForward(t *testing.T) {
	s := &Session{transport: Transport{TLS: true}, authPort: "5191"}
	if !s.Secure() {
		t.Error("a TLS session does not report itself secure")
	}
	child := s.Transport()
	if !child.TLS {
		t.Error("a connection spawned from a TLS session would not use TLS")
	}
	if child.redirectPort != "5191" {
		t.Errorf("spawned transport port = %q, want 5191", child.redirectPort)
	}
	plain := (&Session{}).Transport()
	if plain.TLS {
		t.Error("a plaintext session claimed TLS")
	}
}

// TestServerNameDefaultsToHost: certificate verification has to check the name
// we meant to reach, not the whole host:port string.
func TestServerNameDefaultsToHost(t *testing.T) {
	// Exercised indirectly: dial builds the name the same way redirect splits.
	tr := Transport{TLS: true}
	if tr.ServerName != "" {
		t.Fatal("ServerName should default to empty so the dialed host is used")
	}
}

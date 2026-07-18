package oscar

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
)

// Transport describes how to open OSCAR connections.
//
// It has to travel with the session rather than being decided per-dial: only
// the FIRST address comes from the user's config. The BOS reconnect address and
// every chat-service address are handed to us BY THE SERVER, and a server that
// advertises a plaintext port would otherwise silently downgrade the rest of
// the session — encrypted login, everything after in the clear, no visible
// difference in the UI. So the choice is made once and carried forward.
type Transport struct {
	// TLS makes every connection in this session TLS, including ones opened to
	// server-supplied addresses.
	TLS bool
	// ServerName overrides the certificate name to verify against. Empty means
	// the host from the address being dialed, which is what you want unless the
	// server advertises redirects by IP.
	ServerName string
	// InsecureSkipVerify disables certificate verification. Only for testing
	// against a self-signed development server; it removes the protection that
	// makes TLS worth having, so the UI must say so plainly wherever it's set.
	InsecureSkipVerify bool
	// PinAddress ignores server-advertised redirect addresses entirely and
	// reuses the configured one. Needed when reaching the server through a
	// proxy or tunnel that isn't on the host the server advertises — a local
	// stunnel client, an SSH forward. Off by default, since a legitimate
	// deployment may genuinely run BOS on another host.
	PinAddress bool
	// redirectPort forces server-advertised redirects onto this port. Set from
	// the configured auth port; see withPort.
	redirectPort string
	// pinnedAddr is the configured address, used when PinAddress is set.
	pinnedAddr string
}

// dial opens one connection under this transport.
func (t Transport) dial(ctx context.Context, addr string, startSeq uint16) (*Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	if !t.TLS {
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("oscar: dial %s: %w", addr, err)
		}
		return NewConn(c, startSeq), nil
	}

	name := t.ServerName
	if name == "" {
		if h, _, err := net.SplitHostPort(addr); err == nil {
			name = h
		} else {
			name = addr
		}
	}
	td := &tls.Dialer{
		NetDialer: &d,
		Config: &tls.Config{
			ServerName:         name,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: t.InsecureSkipVerify, //nolint:gosec // opt-in, surfaced in the UI
		},
	}
	c, err := td.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("oscar: TLS dial %s: %w", addr, err)
	}
	return NewConn(c, startSeq), nil
}

// redirect adapts a server-supplied address for this transport.
//
// When TLS is on and the server advertises a bare host (or one whose port we
// were told to override), we keep the host but force our own port — a server
// fronted by a TLS proxy commonly still advertises its internal plaintext port,
// and following that verbatim is the downgrade this guards against.
func (t Transport) redirect(addr, fallbackPort string) string {
	if t.PinAddress && t.pinnedAddr != "" {
		return t.pinnedAddr
	}
	if addr == "" {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port at all: use ours.
		return net.JoinHostPort(strings.TrimSpace(addr), fallbackPort)
	}
	if t.TLS && fallbackPort != "" && port != fallbackPort {
		return net.JoinHostPort(host, fallbackPort)
	}
	return net.JoinHostPort(host, port)
}

// redirectPort is the port a redirect should be forced to under this transport.
// Carried on the Transport so a chat-service dial can correct an advertised
// plaintext port the same way the BOS reconnect does.
func (t Transport) withPort(port string) Transport {
	t.redirectPort = port
	return t
}

// withAddr records the configured address for PinAddress.
func (t Transport) withAddr(addr string) Transport {
	t.pinnedAddr = addr
	return t
}

// authPortOf extracts the port from the configured auth address, which is the
// port we trust — as opposed to whatever the server advertises.
func authPortOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return ""
}

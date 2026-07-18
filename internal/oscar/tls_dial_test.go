package oscar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedListener starts a TLS listener with a throwaway certificate and
// returns its address. It stands in for a development server fronted by
// stunnel with a self-signed cert.
func selfSignedListener(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Complete the handshake, then hold the connection open.
			go func() { _, _ = c.Read(make([]byte, 1)); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// TestTLSDialRejectsUntrustedCert is the test that matters: TLS is worthless if
// we accept any certificate presented to us. A self-signed server must be
// refused unless verification was explicitly disabled.
func TestTLSDialRejectsUntrustedCert(t *testing.T) {
	addr := selfSignedListener(t)

	tr := Transport{TLS: true}
	conn, err := tr.dial(context.Background(), addr, 0)
	if err == nil {
		conn.Close()
		t.Fatal("connected to a server with an untrusted certificate — verification is not happening")
	}
}

// TestTLSDialAcceptsWithSkipVerify covers the development escape hatch, so the
// self-signed testing path is known to work.
func TestTLSDialAcceptsWithSkipVerify(t *testing.T) {
	addr := selfSignedListener(t)

	tr := Transport{TLS: true, InsecureSkipVerify: true}
	conn, err := tr.dial(context.Background(), addr, 0)
	if err != nil {
		t.Fatalf("TLS dial with verification disabled failed: %v", err)
	}
	conn.Close()
}

// TestPlaintextDialUnaffected: the default path must remain a plain TCP dial.
func TestPlaintextDialUnaffected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	conn, err := Transport{}.dial(context.Background(), ln.Addr().String(), 0)
	if err != nil {
		t.Fatalf("plaintext dial broke: %v", err)
	}
	conn.Close()
}

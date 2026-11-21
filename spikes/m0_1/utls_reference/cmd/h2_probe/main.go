// Command h2_probe is an M0.1 test-only Go uTLS client that performs
// an actual TLS 1.3/ALPN h2 handshake and a minimal HTTP/2 request over TCP.
// It is NOT the production Theia TLS backend, nor a complete H2 client.
// No production Rust binary depends on this test tool.
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	modeSuccess     = "ok"
	modeWrongName   = "wrong-name"
	modeUntrustedCA = "untrusted-ca"
	maxFrameSize    = 16_384
)

func validateLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid test TCP address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("test-only uTLS H2 probe refuses non-loopback destinations")
	}
	return nil
}

func tlsProbe(addr, mode string) error {
	if err := validateLoopback(addr); err != nil {
		return err
	}
	pem := os.Getenv("THEIA_TEST_ROOT_PEM")
	if pem == "" {
		return errors.New("THEIA_TEST_ROOT_PEM missing")
	}
	if mode != modeSuccess && mode != modeWrongName && mode != modeUntrustedCA {
		return errors.New("unknown mode")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(pem)) {
		return errors.New("invalid test trust anchor")
	}
	if mode == modeUntrustedCA {
		// Unlike InsecureSkipVerify, an empty trust store MUST reject the peer.
		roots = x509.NewCertPool()
	}
	name := "localhost"
	if mode == modeWrongName {
		name = "wronghost"
	}

	tcp, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("TCP connect: %w", err)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(15 * time.Second))

	conn := utls.UClient(tcp, &utls.Config{
		ServerName: name,
		RootCAs:    roots,
		MinVersion: utls.VersionTLS13,
		MaxVersion: utls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}, utls.HelloChrome_133)
	defer conn.Close()

	err = conn.Handshake()
	if mode == modeWrongName {
		var invalidName x509.HostnameError
		if !errors.As(err, &invalidName) {
			return fmt.Errorf("wrong-host must fail as x509.HostnameError, got: %v", err)
		}
		fmt.Println("uTLS rejected wrong hostname using normal x509 verification")
		return nil
	}
	if mode == modeUntrustedCA {
		var unknownCA x509.UnknownAuthorityError
		if !errors.As(err, &unknownCA) {
			return fmt.Errorf("untrusted-ca must fail as x509.UnknownAuthorityError, got: %v", err)
		}
		fmt.Println("uTLS rejected untrusted CA using normal x509 verification")
		return nil
	}
	if err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}

	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.Version != utls.VersionTLS13 {
		return errors.New("expected verified TLS 1.3 handshake")
	}
	if state.NegotiatedProtocol != "h2" {
		return fmt.Errorf("expected ALPN h2, got %q", state.NegotiatedProtocol)
	}
	if len(state.VerifiedChains) == 0 {
		return errors.New("x509 verified chains missing")
	}
	if err := sendMinimalH2Request(conn); err != nil {
		return err
	}
	if err := receiveH2NoContent(conn); err != nil {
		return err
	}
	fmt.Println("verified uTLS Chrome133 TLS1.3 h2 GET -> 204 over TCP")
	return nil
}

func sendFrame(w io.Writer, typ, flags byte, streamID uint32, payload []byte) error {
	if len(payload) > maxFrameSize || streamID>>31 != 0 {
		return errors.New("invalid HTTP/2 frame")
	}
	var hdr [9]byte
	hdr[0], hdr[1], hdr[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	hdr[3], hdr[4] = typ, flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) != 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

func sendMinimalH2Request(conn io.Writer) error {
	// HTTP/2 connection preface and empty SETTINGS (RFC 9113).
	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"); err != nil {
		return fmt.Errorf("H2 preface: %w", err)
	}
	if err := sendFrame(conn, 4, 0, 0, nil); err != nil {
		return fmt.Errorf("H2 SETTINGS: %w", err)
	}
	// HPACK static-table indexed :method GET (2), :scheme https (7),
	// :path / (4); indexed-name :authority (1), literal "localhost".
	// This is deliberately a basic standards-compliant H2 request, NOT
	// the browser's H2 SETTINGS/priority/pseudo-header fingerprint.
	block := append([]byte{0x82, 0x87, 0x84, 0x01, 0x09}, []byte("localhost")...)
	if err := sendFrame(conn, 1, 0x05, 1, block); err != nil {
		return fmt.Errorf("H2 HEADERS: %w", err)
	}
	return nil
}

func receiveH2NoContent(conn io.ReadWriter) error {
	for count := 0; count < 64; count++ {
		var hdr [9]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return fmt.Errorf("H2 read frame: %w", err)
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		if length > maxFrameSize {
			return errors.New("H2 server frame above default max size")
		}
		typ, flags := hdr[3], hdr[4]
		stream := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		body := make([]byte, length)
		if _, err := io.ReadFull(conn, body); err != nil {
			return fmt.Errorf("H2 read payload: %w", err)
		}
		switch typ {
		case 4: // SETTINGS
			if stream != 0 || (flags&0x01) != 0 && length != 0 {
				return errors.New("invalid H2 SETTINGS")
			}
			if flags&0x01 == 0 {
				if err := sendFrame(conn, 4, 0x01, 0, nil); err != nil {
					return fmt.Errorf("H2 settings ACK: %w", err)
				}
			}
		case 1: // HEADERS
			if stream != 1 || flags&0x05 != 0x05 {
				return errors.New("expected H2 stream 1 final response HEADERS")
			}
			// RFC7541 static table entry 9 encodes :status 204 as 0x89.
			// This simple probe only accepts a single complete 204 response.
			if !bytes.Equal(body, []byte{0x89}) {
				return fmt.Errorf("H2 response not static HPACK :status 204 (length=%d)", len(body))
			}
			return nil
		case 7: // GOAWAY
			return errors.New("H2 server sent GOAWAY")
		}
	}
	return errors.New("too many H2 frames without response")
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: h2_probe <loopback-address> <ok|wrong-name|untrusted-ca>")
		os.Exit(2)
	}
	if err := tlsProbe(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

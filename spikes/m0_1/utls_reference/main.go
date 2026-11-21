// Command utls_reference creates a local, ephemeral Go uTLS H2 ClientHello
// reference, replacing a live browser capture in the M0.1 comparison workflow.
// The raw handshake contains public key shares, randomness and SNI. Never
// log, upload, commit or treat it as a working Chrome/QUIC backend.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	utls "github.com/refraction-networking/utls"
)

const (
	profile  = "go-utls-v1.8.2-HelloChrome_133-tcp-h2"
	maxHello = 65536
)

func generateHello() ([]byte, error) {
	// No socket or handshake; do not weaken any certificate-verification policy.
	conn := utls.UClient(nil, &utls.Config{
		ServerName: "localhost",
		NextProtos: []string{"h2", "http/1.1"},
	}, utls.HelloChrome_133)
	if err := conn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("build Go uTLS ClientHello: %w", err)
	}
	raw := conn.HandshakeState.Hello.Raw
	if len(raw) < 4 || len(raw) > maxHello || raw[0] != 1 {
		return nil, fmt.Errorf("uTLS returned invalid ClientHello frame")
	}
	return raw, nil
}

func run(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: utls_reference <private-output-file>")
	}
	output := args[0]
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("refusing to overwrite an existing output file")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot validate output path: %w", err)
	}
	raw, err := generateHello()
	if err != nil {
		return err
	}
	// Directory must already exist. Exclusive create prevents clobbering.
	file, err := os.OpenFile(filepath.Clean(output), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create private ephemeral ClientHello: %w", err)
	}
	if _, err = file.Write(raw); err != nil {
		file.Close()
		os.Remove(output)
		return fmt.Errorf("write ClientHello: %w", err)
	}
	if err = file.Close(); err != nil {
		os.Remove(output)
		return fmt.Errorf("close ClientHello: %w", err)
	}
	fmt.Printf("generated reference %s (no raw bytes logged)\n", profile)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

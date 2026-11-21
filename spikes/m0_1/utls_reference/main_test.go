package main

import (
    "os"
    "path/filepath"
    "testing"
)

func TestGoUTLSChrome133ClientHello(t *testing.T) {
    hello, err := generateHello()
    if err != nil {
        t.Fatal(err)
    }
    if len(hello) < 4 || hello[0] != 1 {
        t.Fatal("must start with TLS ClientHello handshake type 1")
    }
    length := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
    if length != len(hello)-4 {
        t.Fatalf("ClientHello length mismatch: %d vs %d", length, len(hello)-4)
    }
}

func TestRefusesClobberingExistingFile(t *testing.T) {
    path := filepath.Join(t.TempDir(), "reserved.bin")
    if err := os.WriteFile(path, []byte("sentinel"), 0600); err != nil {
        t.Fatal(err)
    }
    if err := run([]string{path}); err == nil {
        t.Fatal("must not overwrite existing fixture path")
    }
    contents, err := os.ReadFile(path)
    if err != nil || string(contents) != "sentinel" {
        t.Fatal("existing file must stay byte-exact")
    }
}

func TestUsageRequiresExplicitDestination(t *testing.T) {
    if err := run(nil); err == nil {
        t.Fatal("must require explicit destination path")
    }
}

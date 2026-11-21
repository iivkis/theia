package main

import "testing"

func TestH2ProbeIsLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:443", "[::1]:443"} {
		if err := validateLoopback(addr); err != nil {
			t.Fatalf("loopback %q rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{"example.com:443", "192.0.2.3:443", "[2001:db8::2]:443", "bad-address"} {
		if err := validateLoopback(addr); err == nil {
			t.Fatalf("non-loopback %q accepted", addr)
		}
	}
}

package tcpconn

import "testing"

func TestDecodeTargetAddr(t *testing.T) {
	t.Parallel()

	ipv4Raw := [16]uint8{1, 2, 3, 4}
	ipv4, ok := decodeTargetAddr(afInet, ipv4Raw)
	if !ok || ipv4 != "1.2.3.4" {
		t.Fatalf("decodeTargetAddr ipv4 = (%q, %v), want (%q, true)", ipv4, ok, "1.2.3.4")
	}

	ipv6Raw := [16]uint8{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ipv6, ok := decodeTargetAddr(afInet6, ipv6Raw)
	if !ok || ipv6 != "2001:db8::1" {
		t.Fatalf("decodeTargetAddr ipv6 = (%q, %v), want (%q, true)", ipv6, ok, "2001:db8::1")
	}

	if _, ok := decodeTargetAddr(0, [16]uint8{}); ok {
		t.Fatal("decodeTargetAddr unexpectedly accepted unknown family")
	}
}

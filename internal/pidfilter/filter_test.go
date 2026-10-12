package pidfilter

import (
	"testing"
)

func TestParseProcessIdentity(t *testing.T) {
	t.Parallel()

	stat := []byte("123 (worker with spaces) S 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 98765 0")
	got, ok := parseProcessIdentity(stat)
	if !ok {
		t.Fatal("parseProcessIdentity() did not parse valid proc stat")
	}
	want := processIdentity{startTime: 98765}
	if got != want {
		t.Fatalf("parseProcessIdentity() = %+v, want %+v", got, want)
	}
}

func TestParseProcessIdentityRejectsShortStat(t *testing.T) {
	t.Parallel()

	if _, ok := parseProcessIdentity([]byte("123 (worker) S 42")); ok {
		t.Fatal("parseProcessIdentity() parsed a short proc stat")
	}
}

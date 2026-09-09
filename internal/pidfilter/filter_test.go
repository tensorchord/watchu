package pidfilter

import (
	"slices"
	"testing"
)

func TestParseProcessIdentity(t *testing.T) {
	t.Parallel()

	stat := []byte("123 (worker with spaces) S 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 98765 0")
	got, ok := parseProcessIdentity(stat)
	if !ok {
		t.Fatal("parseProcessIdentity() did not parse valid proc stat")
	}
	want := processIdentity{ppid: 42, startTime: 98765}
	if got != want {
		t.Fatalf("parseProcessIdentity() = %+v, want %+v", got, want)
	}
}

func TestDescendants(t *testing.T) {
	t.Parallel()

	processes := map[uint32]processIdentity{
		10: {ppid: 1},
		11: {ppid: 10},
		12: {ppid: 10},
		13: {ppid: 11},
		20: {ppid: 1},
		21: {ppid: 20},
	}

	got := descendants(10, processes)
	slices.Sort(got)
	want := []uint32{10, 11, 12, 13}
	if !slices.Equal(got, want) {
		t.Fatalf("descendants() = %v, want %v", got, want)
	}
}

func TestDescendantsHandlesCycle(t *testing.T) {
	t.Parallel()

	processes := map[uint32]processIdentity{
		10: {ppid: 11},
		11: {ppid: 10},
	}

	got := descendants(10, processes)
	slices.Sort(got)
	want := []uint32{10, 11}
	if !slices.Equal(got, want) {
		t.Fatalf("descendants() = %v, want %v", got, want)
	}
}

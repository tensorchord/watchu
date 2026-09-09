package pidfilter

import (
	"slices"
	"testing"
)

func TestDescendants(t *testing.T) {
	t.Parallel()

	parents := map[uint32]uint32{
		10: 1,
		11: 10,
		12: 10,
		13: 11,
		20: 1,
		21: 20,
	}

	got := descendants(10, parents)
	slices.Sort(got)
	want := []uint32{10, 11, 12, 13}
	if !slices.Equal(got, want) {
		t.Fatalf("descendants() = %v, want %v", got, want)
	}
}

func TestDescendantsHandlesCycle(t *testing.T) {
	t.Parallel()

	parents := map[uint32]uint32{
		10: 11,
		11: 10,
	}

	got := descendants(10, parents)
	slices.Sort(got)
	want := []uint32{10, 11}
	if !slices.Equal(got, want) {
		t.Fatalf("descendants() = %v, want %v", got, want)
	}
}

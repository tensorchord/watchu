package tui

import "testing"

func TestBuildAllTabAnnotationsSimplePair(t *testing.T) {
	t.Parallel()

	records := []displayRecord{
		{Endpoint: "http_request", SessionKey: "s1"},
		{Endpoint: "exec_event"},
		{Endpoint: "http_response", SessionKey: "s1"},
	}

	got := buildAllTabAnnotations(records)

	if len(got) != len(records) {
		t.Fatalf("annotation count = %d, want %d", len(got), len(records))
	}
	if len(got[0].Columns) != 1 || got[0].Columns[0] != pairLinkDot {
		t.Fatalf("request annotation = %+v, want dot", got[0])
	}
	if len(got[1].Columns) != 1 || got[1].Columns[0] != pairLinkPipe {
		t.Fatalf("middle annotation = %+v, want pipe", got[1])
	}
	if len(got[2].Columns) != 1 || got[2].Columns[0] != pairLinkDot {
		t.Fatalf("response annotation = %+v, want dot", got[2])
	}
}

func TestBuildAllTabAnnotationsNestedPairs(t *testing.T) {
	t.Parallel()

	records := []displayRecord{
		{Endpoint: "http_request", SessionKey: "outer"},
		{Endpoint: "http_request", SessionKey: "inner"},
		{Endpoint: "exec_event"},
		{Endpoint: "http_response", SessionKey: "inner"},
		{Endpoint: "http_response", SessionKey: "outer"},
	}

	got := buildAllTabAnnotations(records)

	if len(got[1].Columns) != 2 || got[1].Columns[0] != pairLinkPipe || got[1].Columns[1] != pairLinkDot {
		t.Fatalf("inner request annotation = %+v, want outer pipe + inner dot", got[1])
	}
	if len(got[2].Columns) != 2 || got[2].Columns[0] != pairLinkPipe || got[2].Columns[1] != pairLinkPipe {
		t.Fatalf("inner body annotation = %+v, want two pipes", got[2])
	}
	if len(got[3].Columns) != 2 || got[3].Columns[0] != pairLinkPipe || got[3].Columns[1] != pairLinkDot {
		t.Fatalf("inner response annotation = %+v, want outer pipe + inner dot", got[3])
	}
}

func TestBuildAllTabAnnotationsIgnoresOrphanResponse(t *testing.T) {
	t.Parallel()

	records := []displayRecord{
		{Endpoint: "http_response", SessionKey: "orphan"},
		{Endpoint: "exec_event"},
	}

	got := buildAllTabAnnotations(records)

	for idx, annotation := range got {
		if len(annotation.Columns) != 0 {
			t.Fatalf("annotation[%d] = %+v, want empty annotation", idx, annotation)
		}
	}
}

func TestBuildVisiblePairAnnotationsRestrictsToWindow(t *testing.T) {
	t.Parallel()

	pairs := []pairInterval{
		{Start: 0, End: 4, Level: 0},
		{Start: 1, End: 3, Level: 1},
	}

	got := buildVisiblePairAnnotations(1, 4, pairs, 2)

	if len(got) != 3 {
		t.Fatalf("annotation count = %d, want 3", len(got))
	}
	if len(got[0].Columns) != 2 || got[0].Columns[0] != pairLinkPipe || got[0].Columns[1] != pairLinkDot {
		t.Fatalf("annotation[0] = %+v, want outer pipe + inner dot", got[0])
	}
	if len(got[1].Columns) != 2 || got[1].Columns[0] != pairLinkPipe || got[1].Columns[1] != pairLinkPipe {
		t.Fatalf("annotation[1] = %+v, want two pipes", got[1])
	}
	if len(got[2].Columns) != 2 || got[2].Columns[0] != pairLinkPipe || got[2].Columns[1] != pairLinkDot {
		t.Fatalf("annotation[2] = %+v, want outer pipe + inner dot", got[2])
	}
}

func TestBuildVisiblePairAnnotationsKeepsIndentForRowsOutsidePair(t *testing.T) {
	t.Parallel()

	pairs := []pairInterval{
		{Start: 1, End: 2, Level: 0},
	}

	got := buildVisiblePairAnnotations(0, 4, pairs, 1)

	if len(got) != 4 {
		t.Fatalf("annotation count = %d, want 4", len(got))
	}
	if len(got[0].Columns) != 1 || got[0].Columns[0] != pairLinkNone {
		t.Fatalf("annotation[0] = %+v, want reserved empty gutter", got[0])
	}
	if len(got[3].Columns) != 1 || got[3].Columns[0] != pairLinkNone {
		t.Fatalf("annotation[3] = %+v, want reserved empty gutter", got[3])
	}
}

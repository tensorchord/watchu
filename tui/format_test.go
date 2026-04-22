package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
)

func TestParseJSONLRecordUsesEventTimestamp(t *testing.T) {
	t.Parallel()

	record, err := parseJSONLRecord([]byte(`{
		"endpoint":"http_request",
		"timestamp":"2026-04-21T12:00:05Z",
		"event":{
			"timestamp":"2026-04-21T12:00:01Z",
			"session_key":"s1",
			"method":"GET",
			"url":"https://example.com"
		}
	}`))
	if err != nil {
		t.Fatalf("parseJSONLRecord() error = %v", err)
	}

	want := time.Date(2026, 4, 21, 12, 0, 1, 0, time.UTC)
	if !record.Timestamp.Equal(want) {
		t.Fatalf("record.Timestamp = %s, want %s", record.Timestamp.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestAppendRecordKeepsRecordsSortedByTimestamp(t *testing.T) {
	t.Parallel()

	m := model{
		recordsByTab:   make(map[string][]displayRecord),
		selectedByTab:  make(map[string]int),
		listStartByTab: make(map[string]int),
	}

	late := time.Date(2026, 4, 21, 12, 0, 5, 0, time.UTC)
	early := time.Date(2026, 4, 21, 12, 0, 1, 0, time.UTC)

	m.appendRecord(allTab, displayRecord{
		Endpoint:   "http_response",
		Timestamp:  late,
		SessionKey: "s1",
		Summary:    "resp",
	})
	m.appendRecord(allTab, displayRecord{
		Endpoint:   "http_request",
		Timestamp:  early,
		SessionKey: "s1",
		Summary:    "req",
	})

	records := m.recordsByTab[allTab]
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}
	if records[0].Endpoint != "http_request" || records[1].Endpoint != "http_response" {
		t.Fatalf("record order = [%s, %s], want [http_request, http_response]", records[0].Endpoint, records[1].Endpoint)
	}
}

func TestAppendRecordPreservesSelectionAndViewportOnInsertBefore(t *testing.T) {
	t.Parallel()

	m := model{
		recordsByTab: map[string][]displayRecord{
			allTab: {
				{Endpoint: "exec_event", Summary: "one", Timestamp: time.Date(2026, 4, 21, 12, 0, 1, 0, time.UTC)},
				{Endpoint: "exec_event", Summary: "two", Timestamp: time.Date(2026, 4, 21, 12, 0, 2, 0, time.UTC)},
				{Endpoint: "exec_event", Summary: "three", Timestamp: time.Date(2026, 4, 21, 12, 0, 3, 0, time.UTC)},
			},
		},
		selectedByTab: map[string]int{
			allTab: 1,
		},
		listStartByTab: map[string]int{
			allTab: 1,
		},
	}

	m.appendRecord(allTab, displayRecord{
		Endpoint:  "http_request",
		Summary:   "inserted",
		Timestamp: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC),
	})

	records := m.recordsByTab[allTab]
	if records[0].Summary != "inserted" {
		t.Fatalf("records[0].Summary = %q, want inserted", records[0].Summary)
	}
	if m.selectedByTab[allTab] != 2 {
		t.Fatalf("selectedByTab[all] = %d, want 2", m.selectedByTab[allTab])
	}
	if m.listStartByTab[allTab] != 2 {
		t.Fatalf("listStartByTab[all] = %d, want 2", m.listStartByTab[allTab])
	}
}

func TestSyncDetailViewportResetsToTop(t *testing.T) {
	t.Parallel()

	m := model{
		width:      120,
		height:     20,
		showDetail: true,
		tabIndex:   0,
		detailViewport: viewport.Model{
			YOffset: 8,
		},
		recordsByTab: map[string][]displayRecord{
			allTab: {
				{Endpoint: "exec_event", Timestamp: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC), Detail: "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10"},
			},
		},
		selectedByTab: map[string]int{
			allTab: 0,
		},
		listStartByTab: make(map[string]int),
	}

	m.syncDetailViewport(true)

	if m.detailViewport.YOffset != 0 {
		t.Fatalf("detailViewport.YOffset = %d, want 0", m.detailViewport.YOffset)
	}
}

func TestRenderDetailDoesNotExceedWindowWidth(t *testing.T) {
	t.Parallel()

	m := model{
		width:      40,
		height:     20,
		showDetail: true,
		tabIndex:   0,
		recordsByTab: map[string][]displayRecord{
			allTab: {
				{
					Endpoint:  "http_request",
					Timestamp: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC),
					Detail:    `{"very_long_key":"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"}`,
				},
			},
		},
		selectedByTab: map[string]int{
			allTab: 0,
		},
		listStartByTab: make(map[string]int),
	}

	m.syncDetailViewport(true)
	rendered := m.renderDetail(6)
	if got := lipgloss.Width(rendered); got > m.width {
		t.Fatalf("renderDetail width = %d, want <= %d", got, m.width)
	}
}

func TestSyncDetailViewportWrapsLongDetailLines(t *testing.T) {
	t.Parallel()

	m := model{
		width:      24,
		height:     12,
		showDetail: true,
		tabIndex:   0,
		recordsByTab: map[string][]displayRecord{
			allTab: {
				{
					Endpoint:  "http_request",
					Timestamp: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC),
					Detail:    "abcdefghijklmnopqrstuvwxyz",
				},
			},
		},
		selectedByTab: map[string]int{
			allTab: 0,
		},
		listStartByTab: make(map[string]int),
	}

	m.syncDetailViewport(true)
	rendered := m.renderDetail(6)
	if !strings.Contains(rendered, "abcdefghijklmnopqrst") || !strings.Contains(rendered, "uvwxyz") {
		t.Fatalf("renderDetail() did not appear to wrap long detail lines:\n%s", rendered)
	}
}

func TestRenderListDoesNotExceedWindowWidth(t *testing.T) {
	t.Parallel()

	m := model{
		width:    40,
		height:   20,
		tabIndex: 0,
		recordsByTab: map[string][]displayRecord{
			allTab: {
				{
					Endpoint:  "http_request",
					Timestamp: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC),
					Summary:   "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
				},
			},
		},
		selectedByTab: map[string]int{
			allTab: 0,
		},
		listStartByTab: make(map[string]int),
	}

	rendered := m.renderList(4)
	if got := lipgloss.Width(rendered); got > m.width {
		t.Fatalf("renderList width = %d, want <= %d", got, m.width)
	}
}

func TestRenderListDoesNotExceedBodyHeight(t *testing.T) {
	t.Parallel()

	m := model{
		width:    40,
		height:   10,
		tabIndex: 0,
		recordsByTab: map[string][]displayRecord{
			allTab: {
				{Endpoint: "exec_event", Timestamp: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC), Summary: "one"},
				{Endpoint: "exec_event", Timestamp: time.Date(2026, 4, 21, 12, 0, 1, 0, time.UTC), Summary: "two"},
				{Endpoint: "exec_event", Timestamp: time.Date(2026, 4, 21, 12, 0, 2, 0, time.UTC), Summary: "three"},
			},
		},
		selectedByTab: map[string]int{
			allTab: 0,
		},
		listStartByTab: make(map[string]int),
	}

	rendered := m.renderList(4)
	if got := lipgloss.Height(rendered); got > 4 {
		t.Fatalf("renderList height = %d, want <= 4", got)
	}
}

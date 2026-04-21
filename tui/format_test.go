package tui

import (
	"testing"
	"time"
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

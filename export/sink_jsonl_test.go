package export

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilePathFromTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		want    string
		wantErr string
	}{
		{
			name:   "absolute file path",
			target: "file:///tmp/watchu.jsonl",
			want:   "/tmp/watchu.jsonl",
		},
		{
			name:   "localhost host accepted",
			target: "file://localhost/tmp/watchu.jsonl",
			want:   "/tmp/watchu.jsonl",
		},
		{
			name:    "invalid scheme",
			target:  "ftp:///tmp/watchu.jsonl",
			wantErr: "invalid file export target",
		},
		{
			name:    "non localhost host rejected",
			target:  "file://remote/tmp/watchu.jsonl",
			wantErr: "must not include host",
		},
		{
			name:    "relative path rejected",
			target:  "file:relative.jsonl",
			wantErr: "must include an absolute path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := FilePathFromTarget(tt.target)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("FilePathFromTarget(%q) error = %v, want substring %q", tt.target, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FilePathFromTarget(%q) returned error: %v", tt.target, err)
			}
			if got != tt.want {
				t.Fatalf("FilePathFromTarget(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

func TestNewSink(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	fileTarget := "file://" + filepath.ToSlash(filepath.Join(tempDir, "watchu.jsonl"))

	tests := []struct {
		name     string
		target   string
		wantErr  string
		wantType any
	}{
		{name: "empty target uses discard", target: "", wantType: &DiscardSink{}},
		{name: "file target uses jsonl sink", target: fileTarget, wantType: &JSONLSink{}},
		{name: "invalid target rejected", target: "unix:///tmp/watchu.sock", wantErr: "invalid --export"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sink, err := NewSink(context.Background(), tt.target)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewSink(%q) error = %v, want substring %q", tt.target, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewSink(%q) returned error: %v", tt.target, err)
			}
			defer sink.Close()

			switch tt.wantType.(type) {
			case *DiscardSink:
				if _, ok := sink.(*DiscardSink); !ok {
					t.Fatalf("NewSink(%q) returned %T, want *DiscardSink", tt.target, sink)
				}
			case *JSONLSink:
				if _, ok := sink.(*JSONLSink); !ok {
					t.Fatalf("NewSink(%q) returned %T, want *JSONLSink", tt.target, sink)
				}
			}
		})
	}
}

func TestJSONLSinkWriteBatchAndClose(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := NewJSONLSink("file://" + filepath.ToSlash(path))
	if err != nil {
		t.Fatalf("NewJSONLSink returned error: %v", err)
	}

	events := []any{
		map[string]any{"op": "open", "path": "/etc/passwd"},
		map[string]any{"op": "write", "path": "/tmp/out"},
	}
	if err := sink.WriteBatch(context.Background(), "file_op", events); err != nil {
		t.Fatalf("WriteBatch returned error: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if err := sink.WriteBatch(context.Background(), "file_op", events); err == nil {
		t.Fatal("WriteBatch unexpectedly succeeded after Close")
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var records []JSONLRecord
	for scanner.Scan() {
		var record JSONLRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("failed to unmarshal record: %v", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner returned error: %v", err)
	}
	if len(records) != len(events) {
		t.Fatalf("record count = %d, want %d", len(records), len(events))
	}
	if records[0].Endpoint != "file_op" {
		t.Fatalf("first endpoint = %q, want %q", records[0].Endpoint, "file_op")
	}
	if records[0].Timestamp.IsZero() {
		t.Fatal("first record timestamp was zero")
	}
}

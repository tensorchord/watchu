package tool

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCharsToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []int8
		want string
	}{
		{name: "stops at null terminator", in: []int8{'h', 'i', 0, 'x'}, want: "hi"},
		{name: "uses full slice without null", in: []int8{'o', 'k'}, want: "ok"},
		{name: "empty slice", in: nil, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := CharsToString(tt.in); got != tt.want {
				t.Fatalf("CharsToString(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadCloserToBytes(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		got, err := ReadCloserToBytes(io.NopCloser(strings.NewReader("hello")))
		if err != nil {
			t.Fatalf("ReadCloserToBytes returned error: %v", err)
		}
		if string(got) != "hello" {
			t.Fatalf("ReadCloserToBytes returned %q, want %q", got, "hello")
		}
	})

	t.Run("closes on read error", func(t *testing.T) {
		t.Parallel()

		rc := &readErrorCloser{err: errors.New("boom")}
		_, err := ReadCloserToBytes(rc)
		if err == nil {
			t.Fatal("ReadCloserToBytes unexpectedly succeeded")
		}
		if !rc.closed {
			t.Fatal("ReadCloserToBytes did not close the reader on error")
		}
	})
}

func TestIsFilePath(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "sample.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		want    bool
		wantErr bool
	}{
		{name: "regular file", path: filePath, want: true},
		{name: "directory", path: tempDir, want: false},
		{name: "missing path", path: filepath.Join(tempDir, "missing"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := IsFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsFilePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("IsFilePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

type readErrorCloser struct {
	err    error
	closed bool
}

func (r *readErrorCloser) Read(_ []byte) (int, error) {
	return 0, r.err
}

func (r *readErrorCloser) Close() error {
	r.closed = true
	return nil
}

package main

import (
	"context"
	"errors"
	"syscall"
	"testing"
)

func TestNormalizeShutdownCause(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "nil", err: nil, want: nil},
		{name: "context canceled", err: context.Canceled, want: context.Canceled},
		{name: "sigint notify cause", err: errors.New(syscall.SIGINT.String() + " signal received"), want: context.Canceled},
		{name: "sigterm notify cause", err: errors.New(syscall.SIGTERM.String() + " signal received"), want: context.Canceled},
		{name: "other error", err: boom, want: boom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeShutdownCause(tt.err)
			if !errors.Is(got, tt.want) {
				t.Fatalf("normalizeShutdownCause(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

//go:build linux && (amd64 || arm64)

package fileop

import "testing"

func TestUnsupportedFileOpTracepoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		goarch     string
		tracepoint string
		want       bool
	}{
		{name: "arm64 open", goarch: "arm64", tracepoint: "sys_enter_open", want: true},
		{name: "arm64 open exit", goarch: "arm64", tracepoint: "sys_exit_open", want: true},
		{name: "arm64 rename", goarch: "arm64", tracepoint: "sys_enter_rename", want: true},
		{name: "arm64 hardlink", goarch: "arm64", tracepoint: "sys_enter_link", want: true},
		{name: "arm64 symlink", goarch: "arm64", tracepoint: "sys_enter_symlink", want: true},
		{name: "arm64 openat", goarch: "arm64", tracepoint: "sys_enter_openat", want: false},
		{name: "arm64 renameat", goarch: "arm64", tracepoint: "sys_enter_renameat", want: false},
		{name: "amd64 legacy open", goarch: "amd64", tracepoint: "sys_enter_open", want: false},
		{name: "other arch legacy open", goarch: "riscv64", tracepoint: "sys_enter_open", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := unsupportedFileOpTracepoint(tt.goarch, tt.tracepoint)
			if got != tt.want {
				t.Fatalf("unsupportedFileOpTracepoint(%q, %q) = %v, want %v", tt.goarch, tt.tracepoint, got, tt.want)
			}
		})
	}
}

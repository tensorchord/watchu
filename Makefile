.DEFAULT_GOAL := build

update_header:
	@cd headers && bash update.sh

gen_vmlinux:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

gen_ebpf:
	@go generate ./...

build: gen_ebpf
	@CGO_ENABLED=0 go build -o bin/app cmd/main.go

build-securityinsight:
	@CGO_ENABLED=0 go build -o bin/securityinsight cmd/securityinsight/main.go

format:
	@go fmt ./...
	@golangci-lint fmt
	@find . -type f -name "*.c" | xargs clang-format -i

lint-ebpf:
	@find . -type f -name "*.c" | xargs clang-format --dry-run --Werror

lint-go:
	@golangci-lint run

lint: lint-ebpf lint-go

test: gen_ebpf
	@go test ./...

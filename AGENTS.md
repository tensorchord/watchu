# WatchU Repo Guide

## Top-level folder responsibilities:

- `cmd`: Application entrypoint.
- `export`: Event normalization and sinks. Converts raw probe output into exported records and writes to a gateway, local JSONL files, or discard.
- `headers`: Shared eBPF headers and helper files used by the C probes. Includes vendored/libbpf-style headers and update scripts.
- `internal`:
  - `container`: container ID resolution
  - `logger`: logger setup
  - `proc`: process and library discovery helpers
  - `tool`: common runtime helpers and misc utilities
- `otelrecv`: OTLP gRPC receiver for AI tool telemetry ingestion.
- `tui`: Terminal UI for viewing locally exported JSONL events.

### Probe folders

- `execve`: Process exec eBPF probe and userspace ingestion logic.
- `fileop`: File operation eBPF probe, policy loading, and userspace export path.
- `postgres`: Postgres plaintext probe and userspace ingestion.
- `stdio`: stdio eBPF probe and MCP/stdout-stderr event ingestion.
- `tcpconn`: TCP connect probe and exported connection events.
- `tls`: TLS plaintext capture and protocol parsing. Handles OpenSSL/BoringSSL hooks, HTTP/1, HTTP/2, Postgres-over-TLS parsing, compression decoding, and request/response correlation.

## Update probe workflow

- Any change to probe C code or shared eBPF headers should be followed by `make gen_ebpf`.

### Generated artifacts and related files

- `*_x86_bpfel.go`: Go bindings generated from eBPF object files. Do not hand-edit.
- `*.o`: eBPF object files generated from the C probes. Do not hand-edit.
- `*.bpf.c`: Source for the eBPF probes. Changes here usually require regeneration.

## Working agreements

- `make gen_ebpf`: Run this when you change any eBPF C source, shared eBPF headers, or Go generate inputs that affect generated probe bindings.
- `make format && make lint`: Run this when you change Go code, C/eBPF code, or test code.
- `make test`: This is the default verification step for most code changes.

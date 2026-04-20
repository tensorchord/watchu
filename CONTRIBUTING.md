# Contributing

Thanks for contributing to WatchU.

## Development Environment

The recommended way to work on this repository is to use the same container image used by CI:

```bash
docker run --rm \
  -v "$PWD":/workspace \
  -w /workspace \
  ghcr.io/tensorchord/ebpf-builder:0.2.0 \
  bash -c "make"
```

This gives you a reproducible development environment with the expected toolchain for eBPF generation and Golang compilation.

If you prefer to work directly on your host, make sure the required tools are installed and compatible with the versions expected by the repository.

## Common Commands

- `make build`
  Build the application.

- `make lint`
  Run Go and eBPF formatting/lint checks.

- `make test`
  Run the test suite.

- `make gen_ebpf`
  Regenerate eBPF bindings after changing probe C code, shared eBPF headers, or related generate inputs.

Typical workflow:

```bash
make gen_ebpf   # if you changed probe C code or shared eBPF headers
make format
make lint
make test
```

## Before You Commit

Please run the relevant checks locally before opening a PR.

If you use pre-commit tooling, we recommend:

- `prek`: https://github.com/j178/prek
- or any other pre-commit hook runner you already use

The goal is simple: run formatting before committing so review stays focused on the change itself instead of avoidable CI failures.

## Pull Requests

A good pull request should include:

- a clear description of the problem and the change
- notes about any behavior change or compatibility impact
- tests for new behavior when practical
- regenerated artifacts when required

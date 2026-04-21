<div align="center">

<img width="196" src="https://github.com/user-attachments/assets/fa28f01c-b500-4f06-ac8f-bcdcd99d9f42" alt="WatchU logo">

<p>

[![Build & Test][ci-check-badge]][ci-check-file]
[![Discord][discord-badge]][discord-link]

</p>
</div>

WatchU is a Linux eBPF-based collector for observing agent activities from the host.

It is designed for people who want a local collector that can capture high-value runtime signals such as:

- [x] process execs
- [x] file operations
- [x] TLS plaintext HTTP traffic (OpenSSL & BoringSSL)
- [x] TCP connects
- [x] Postgres client queries
- [x] stdio/MCP traffic

![demo](https://github.com/user-attachments/assets/1a5aeab5-3612-4694-a72a-59c2654f753b)

## Requirements

Current expected runtime environment:

- Linux `amd64` with kernel version >= 5.8
- Permissions to load eBPF programs and attach fentry/uprobe/tracepoints

## Quick Start

Build:

```bash
make build
```

Run with debug logging:

```bash
sudo ./bin/app -debug
```

Run with the terminal UI:

```bash
sudo ./bin/app -tui
```

Export events to a local JSONL file:

```bash
sudo ./bin/app -export file:///tmp/watchu.jsonl
```

## Docker Quick Start

Build the image:

```bash
docker buildx build -t watchu -f Dockerfile --load .
```

Run it:

```bash
docker run --rm \
  --cap-add=CAP_SYS_ADMIN \
  --cap-add=CAP_SYS_PTRACE \
  --cap-add=CAP_BPF \
  --cap-add=CAP_PERFMON \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  --pid=host \
  --security-opt apparmor=unconfined \
  watchu
```

## Development

Check the [CONTRIBUTING.md](./CONTRIBUTING.md) guide.


[ci-check-badge]: https://github.com/tensorchord/watchu-cli/actions/workflows/build.yml/badge.svg
[ci-check-file]: https://github.com/tensorchord/watchu-cli/actions/workflows/build.yml
[discord-badge]: https://img.shields.io/discord/974584200327991326?&logoColor=white&color=5865F2&style=flat&logo=discord&cacheSeconds=60
[discord-link]: https://discord.gg/KqswhpVgdU

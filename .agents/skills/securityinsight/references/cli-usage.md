# Security Insight CLI Reference

The `securityinsight` CLI is a **pure data collector** — it gathers and shapes telemetry but applies no security rules. All classification and judgment is deferred to the calling agent.

## Commands

```bash
securityinsight collect threat [options]   # Threat evidence (scan or detail)
securityinsight collect prompt [options]   # Prompt injection evidence
```

## Common Options

| Flag                  | Type   | Default  | Description                                                                                |
| --------------------- | ------ | -------- | ------------------------------------------------------------------------------------------ |
| `--input`             | string | —        | **Required.** JSONL file path or glob pattern                                              |
| `--format`            | string | `prompt` | Output format: `prompt` (human-readable) or `json`                                         |
| `--max-events`        | int    | `50`     | Max events in output                                                                       |
| `--max-agent-output`  | int    | `12000`  | Max total chars for agent output excerpts (keyword-matched lines from agent stderr/stdout) |
| `--max-snippet-chars` | int    | `4000`   | Max chars per field in each LLM call record (response body gets half)                      |
| `--max-llm-calls`     | int    | `25`     | Max LLM API request/response pairs in output                                               |

## `collect threat` Options

### Target Resolution

Mutually exclusive — pick one:

| Flag                  | Type   | Description                                  |
| --------------------- | ------ | -------------------------------------------- |
| `--latest`            | bool   | Auto-resolve the most recent agent run       |
| `--root-exec-id`      | string | Target a specific root execution ID          |
| `--since` + `--until` | string | RFC3339 time window (both required together) |

### Mode and Focus

| Flag       | Type   | Default | Description                                                                |
| ---------- | ------ | ------- | -------------------------------------------------------------------------- |
| `--mode`   | string | `scan`  | `scan` (compact overview) or `detail` (raw event timeline)                 |
| `--focus`  | string | —       | **Required when `--mode=detail`.** Category to inspect                     |
| `--filter` | string | —       | Pipe-separated patterns for detail mode (case-insensitive substring match) |

Available `--focus` values:

| Value        | Description                              |
| ------------ | ---------------------------------------- |
| `exec`       | Process executions (commands, arguments) |
| `file_read`  | File read operations                     |
| `file_write` | File write/rename/unlink operations      |
| `network`    | TCP connections (destinations)           |
| `http`       | HTTP requests (method, URL, body size)   |
| `mcp`        | MCP stdio messages (tool calls)          |
| `all`        | All categories merged into one timeline  |

## `collect prompt` Options

### Target Resolution

Mutually exclusive — pick one:

| Flag                  | Type   | Description                                  |
| --------------------- | ------ | -------------------------------------------- |
| `--root-exec-id`      | string | Collect for an explicit root execution ID    |
| `--since` + `--until` | string | RFC3339 time window (both required together) |

### Additional

| Flag     | Type   | Description                                                                               |
| -------- | ------ | ----------------------------------------------------------------------------------------- |
| `--host` | string | Host to analyze (optional, auto-detected if omitted; only valid with `--since`/`--until`) |

> `--latest` is **not** available for `collect prompt`.

## Examples

### Scan

```bash
securityinsight collect threat --mode=scan --input=/tmp/agent.json --latest
securityinsight collect threat --mode=scan --input=/tmp/agent.json \
  --since="2026-04-02T09:55:00+08:00" --until="2026-04-02T10:05:00+08:00"
```

### Detail

```bash
securityinsight collect threat --mode=detail --focus=exec --input=/tmp/agent.json --latest
securityinsight collect threat --mode=detail --focus=file_read --filter="shadow|passwd|ssh" \
  --input=/tmp/agent.json --latest
securityinsight collect threat --mode=detail --focus=http --input=/tmp/agent.json --latest
```

### Prompt collection

```bash
securityinsight collect prompt --input=/tmp/agent.json --root-exec-id="$ROOT_ID"
securityinsight collect prompt --input=/tmp/agent.json \
  --since="2026-04-02T09:55:00+08:00" --until="2026-04-02T10:05:00+08:00"
```

### JSON output

```bash
securityinsight collect threat --mode=scan --input=/tmp/agent.json --latest --format=json
securityinsight collect threat --mode=detail --focus=exec --input=/tmp/agent.json --latest --format=json
```

## Notes

- Use `prompt` format when the agent reads output directly; use `json` for debugging or programmatic post-processing.
- **`--latest` is the preferred target selector.** Only use `--since`/`--until` when you need a precise time window.
- `--since`/`--until` require **RFC3339 format** (e.g., `2026-04-16T09:00:00+08:00` or `2026-04-16T01:00:00Z`). The timezone offset **must** use a colon: `+08:00`, not `+0800`. Use `date +%:z` or UTC with `Z` to avoid this pitfall.
- When multiple agent runs exist in a time window, scan mode outputs one package per run.

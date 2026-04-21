---
name: securityinsight
description: Analyze agent execution telemetry collected by the local securityinsight CLI using a two-phase scan/detail workflow and return a structured security verdict.
version: 0.1.0
allowed-tools: Bash, Read
---

# Security Insight

Use this skill to analyze agent-related security telemetry gathered by the local `securityinsight` CLI.

## When To Use

Use this skill when you need to:

- assess one recent or time-bounded agent execution for security threats
- review prompt injection evidence for a host and time window
- synthesize telemetry into one structured security verdict

Do not use this skill for direct database exploration, generic code review, or infrastructure audits unrelated to agent execution.

## Workflow

The threat analysis workflow uses a **two-phase scan/detail** approach. The CLI is a pure data collector — it applies no security rules. All classification and judgment is your responsibility.

### Target Selection

Choose a target in this priority order:

1. **`--latest`** (preferred) — auto-resolves the most recent agent run. Use this when the user says "latest", "most recent", or gives a relative time phrase like "last 6 hours" without needing a precise window.
2. **`--root-exec-id="$ID"`** — target a specific run by ID (from a prior scan result).
3. **`--since` + `--until`** — explicit RFC3339 time window. Only use when the user needs a precise range.

> **Always try `--latest` first.** Only fall back to `--since`/`--until` when the user explicitly requires a specific time window or when `--latest` selects the wrong run.

When you must convert a relative time phrase to RFC3339:

```bash
# UTC (recommended — avoids timezone pitfalls)
SINCE=$(date -u -d "6 hours ago" +%Y-%m-%dT%H:%M:%SZ)
UNTIL=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Local timezone — use %:z (colon-separated), NOT %z
SINCE=$(date -d "6 hours ago" +%Y-%m-%dT%H:%M:%S%:z)
UNTIL=$(date +%Y-%m-%dT%H:%M:%S%:z)
```

> **Warning:** `date +%z` outputs `+0800` which is NOT valid RFC3339. You must use `+%:z` to get `+08:00` (colon-separated), or use UTC with a trailing `Z`.

### Phase 1: Scan

Run `securityinsight collect threat --mode=scan` to get a compact overview (~2K tokens) of an agent run. The output includes:

- telemetry summary (event counts by type)
- event overview (per-category counts + top items by frequency)
- process tree skeleton (up to 3 levels deep)
- runner output excerpts (security-keyword-matched lines)

Scan commands:

```bash
# Preferred: latest run
securityinsight collect threat --mode=scan --input="$JSONL" --latest --format=prompt

# Explicit time window (RFC3339 only)
securityinsight collect threat --mode=scan --input="$JSONL" --since="$SINCE" --until="$UNTIL" --format=prompt
```

### Phase 2: Detail (1–3 targeted deep-dives)

Based on what the scan reveals, pick **one to three** categories to inspect in detail:

```bash
securityinsight collect threat --mode=detail --focus=exec --input="$JSONL" --latest --format=prompt
securityinsight collect threat --mode=detail --focus=file_read --filter="shadow|passwd" --input="$JSONL" --latest --format=prompt
securityinsight collect threat --mode=detail --focus=http --input="$JSONL" --latest --format=prompt
```

Available focus categories:

| Focus | Description |
|---|---|
| `exec` | Process executions (commands, arguments) |
| `file_read` | File read operations |
| `file_write` | File write/rename/unlink operations |
| `network` | TCP connections (destinations) |
| `http` | HTTP requests (method, URL, body size) |
| `mcp` | MCP stdio messages (tool calls) |
| `all` | All categories merged into one timeline |

Use `--filter="term1|term2"` to narrow results by pipe-separated patterns (case-insensitive substring match).

### Phase 3: Optional Prompt Collection

If threat evidence hints at prompt injection, instruction override, or suspicious prompt-channel abuse, follow up with prompt collection:

```bash
securityinsight collect prompt --input="$JSONL" --root-exec-id="$ROOT_EXEC_ID" --format=prompt
securityinsight collect prompt --input="$JSONL" --since="$SINCE" --until="$UNTIL" --format=prompt
```

### Phase 4: Verdict

After gathering sufficient evidence from phases 1–3, produce exactly one human-readable Markdown verdict matching the report format in `references/output-schema.md`.

## Decision Guide

### Step 1: Read the Scan

Check the scan overview and classify the situation:

| Scan Signal | Severity Hint | Next Action |
|---|---|---|
| Red flags or suspicious sequences present | HIGH–CRITICAL | Jump to Step 2 with flagged categories |
| Multiple categories have elevated counts | MEDIUM–HIGH | Prioritize by the order in Step 2 |
| Only one category looks unusual | LOW–MEDIUM | Single detail deep-dive on that category |
| All counts near zero or telemetry looks incomplete | UNKNOWN | Go to Step 4 (data quality check) |
| Everything looks normal, no flags | NONE | Verdict: Threat Level = 0 (none, scale 0-4) |

### Step 2: Prioritized Detail Deep-Dives (max 3)

Inspect categories in this priority order — higher priority means higher blast radius:

1. **exec** — unexpected commands (`curl`, `wget`, `chmod`, `base64`, reverse shells, package installs)
2. **network** — connections to external IPs, unexpected ports, non-standard destinations
3. **file_write** — writes to sensitive paths (`/etc/`, `~/.ssh/`, crontabs, startup scripts)
4. **http** — requests to unknown hosts, large POST bodies, non-LLM API endpoints
5. **file_read** — reads of credentials, secrets, env files, `/etc/shadow`, private keys
6. **mcp** — unusual tool names, unexpected MCP servers, tool calls with suspicious arguments

After each detail result, check if it reveals a **new category** to investigate:
- `detail(exec)` shows `curl` to unknown host → also run `detail(http)` or `detail(network)`
- `detail(file_read)` shows credential access → also run `detail(network)` to check exfiltration
- `detail(mcp)` shows tool writing files → also run `detail(file_write)`

This iterative approach replaces the single-pass routing from Phase 1.

### Step 3: Known Attack Pattern Matching

Cross-reference detail findings against these known kill chains:

| Pattern | Trigger | Follower | Interpretation |
|---|---|---|---|
| **Data exfiltration** | `file_read` on secrets/credentials/env | `network` or `http` POST to external host | Credential theft or data leak |
| **Persistent backdoor** | `file_write` to `~/.ssh/authorized_keys`, crontab, or systemd units | `exec` of ssh-keygen or cron reload | Persistence mechanism |
| **Reverse shell** | `exec` of `bash -i`, `nc -e`, `python -c 'import socket'` | `network` to external IP on non-standard port | Active C2 channel |
| **Supply chain attack** | `exec` of `pip install`, `npm install`, `curl \| sh` | `file_write` outside expected paths | Trojan dependency |
| **Privilege escalation** | `exec` of `sudo`, `chmod +s`, `chown root` | `file_write` to system directories | Privesc attempt |
| **Anti-forensic** | `file_write` deleting logs, `.bash_history` | Low overall event count despite long runtime | Evidence tampering |

If any pattern matches, elevate severity by one level (e.g., MEDIUM → HIGH).

### Step 4: Data Quality Check

Before finalizing a "clean" verdict, verify the telemetry is trustworthy:

- **Event count sanity**: A 10-minute agent session should typically produce dozens to hundreds of events. If total events < 5, suspect incomplete telemetry rather than "nothing happened."
- **Category coverage**: If exec events exist but file_ops are zero, the exporter may not have captured file operations. Note this as a coverage gap.
- **Time gap analysis**: If there are large gaps (>60s) in the event timeline during an active session, note as potential telemetry loss.
- **Budget truncation**: If the scan notes mention truncation, increase `--max-events` and re-run before concluding.

When telemetry appears incomplete, the verdict should include a **confidence qualifier** (e.g., "LOW confidence — telemetry appears incomplete").

### Step 5: Prompt Injection Triggers

Escalate to `collect prompt` when **any** of these conditions are met:

| Trigger | Where to Look |
|---|---|
| Runner excerpts contain keywords: `ignore previous`, `system prompt`, `you are now`, `disregard`, `new instructions` | Scan runner excerpts |
| MCP tool calls with unexpected tool names or arguments containing encoded payloads | `detail(mcp)` |
| `file_read` of prompt templates, system instructions, or `.env` files followed by LLM API calls | `detail(file_read)` + `detail(http)` |
| HTTP requests to LLM APIs with abnormally large request bodies (>10KB) | `detail(http)` |
| Agent output shows refusal messages followed by compliance (refusal bypass) | Scan runner excerpts |
| Red flags flagged any `S*_prompt_injection` pattern | Scan red flags |

```
collect prompt --input="$JSONL" --root-exec-id="$ROOT_EXEC_ID" --format=prompt
```

### Step 6: Verdict

Synthesize all evidence into a single Markdown verdict per `references/output-schema.md`.

## References

- CLI usage: [references/cli-usage.md](./references/cli-usage.md)
- Output schema: [references/output-schema.md](./references/output-schema.md)

## Required Output

Return exactly one Markdown verdict matching the report format in `references/output-schema.md`.

## Key Rules

- **You MUST use the `securityinsight` CLI for all evidence collection.**
- **The CLI applies NO security rules** — all classification, severity, and judgment is your responsibility.
- The final answer is for a human reading a CLI transcript. Do not emit raw JSON unless the user explicitly asks for machine-readable output.
- Treat CLI budget notes as truncation metadata, not as evidence gaps.
- Prefer concrete observed behavior over speculation.
- Treat explicit refusal by the agent as mitigating evidence, not proof of compromise.
- The two-phase workflow is designed to keep token budgets low. Do **not** use `--focus=all` unless the scan overview is ambiguous and a targeted focus is not possible.

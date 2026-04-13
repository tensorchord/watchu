# OpenTelemetry Receiver for AI Coding Tools

This package provides an OTLP (OpenTelemetry Protocol) gRPC receiver for capturing telemetry from AI coding tools. This is an **alternative to SSL interception** for observing LLM prompts and responses.

## Supported Tools

| Tool | Event Prefix | Configuration |
|------|--------------|---------------|
| **OpenAI Codex CLI** | `codex.*` | `~/.codex/config.toml` |
| **Claude Code** | `claude_code.*` | Environment variables |
| **Gemini CLI** | `gemini_cli.*` | `.gemini/settings.json` |

## Event Types Captured

| Event Type | Codex | Claude Code | Gemini CLI |
|------------|-------|-------------|------------|
| User Prompt | `codex.user_prompt` | `claude_code.user_prompt` | `gemini_cli.user_prompt` |
| API Request | `codex.api_request` | `claude_code.api_request` | `gemini_cli.api_request` |
| API Response | `codex.sse_event` | `claude_code.api_request` | `gemini_cli.api_response` |
| Tool Result | `codex.tool_result` | `claude_code.tool_result` | `gemini_cli.tool_call` |
| Tool Decision | `codex.tool_decision` | `claude_code.tool_decision` | - |

## Setup

### 1. Start the Collector with OTEL Receiver

```bash
./watchu --otel-addr=:4317 --export=http://localhost:8080
```

### 2. Configure Your AI Coding Tool

#### OpenAI Codex CLI

Ref: https://developers.openai.com/codex/security/#enable-otel-opt-in

Edit `~/.codex/config.toml`:

```toml
[otel]
environment = "dev"
log_user_prompt = true
exporter = { otlp-grpc = {
  endpoint = "http://localhost:4317",
}}
```

#### Claude Code

Ref: https://code.claude.com/docs/en/monitoring-usage

Set environment variables:

```bash
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_METRICS_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
export OTEL_LOG_USER_PROMPTS=1
```

#### Gemini CLI

Ref: https://geminicli.com/docs/cli/telemetry/

Edit `~/.gemini/settings.json`:

```json
{
  "telemetry": {
    "enabled": true,
    "target": "local",
    "otlpEndpoint": "http://localhost:4317",
    "otlpProtocol": "grpc",
    "logPrompts": true
  }
}
```

## Event Schema

### Common Fields

| Field | Description |
|-------|-------------|
| `tool` | Source tool: `codex`, `claude_code`, or `gemini_cli` |
| `event_name` | Full event name (e.g., `codex.user_prompt`) |
| `event_type` | Event type (e.g., `user_prompt`, `api_request`) |
| `model` | LLM model used |
| `prompt` | User prompt text (if enabled) |
| `prompt_length` | Length of prompt |

### Tool-Specific Fields

| Field | Tools | Description |
|-------|-------|-------------|
| `conversation_id` | Codex | Thread/conversation identifier |
| `session_id` | Claude, Gemini | Session identifier |
| `cost_usd` | Claude | Estimated cost in USD |
| `decision` | Claude, Gemini | Tool accept/reject decision |

## Architecture

```
┌─────────────┐     OTLP/gRPC      ┌──────────────────┐     HTTP      ┌─────────┐
│  Codex CLI  │ ─────────────────▶ │                  │               │         │
├─────────────┤                    │  watchu OTEL Rx  │ ────────────▶ │ Gateway │
│ Claude Code │ ─────────────────▶ │                  │               │         │
├─────────────┤                    │  Parses events   │               │         │
│ Gemini CLI  │ ─────────────────▶ │  from all tools  │               │         │
└─────────────┘                    └──────────────────┘               └─────────┘
```

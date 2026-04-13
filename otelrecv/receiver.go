// Package otelrecv provides an OpenTelemetry OTLP receiver for capturing
// telemetry from AI coding tools like Codex, Claude Code, and Gemini CLI.
package otelrecv

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/phuslu/log"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/tensorchord/watchu/export"
)

type OTELReceiver struct {
	collogspb.UnimplementedLogsServiceServer

	grpcServer *grpc.Server
	listener   net.Listener
	eventChan  chan *export.RecordAgentEvent
	exporter   *export.Exporter
}

const (
	ToolCodex      = "codex"
	ToolClaudeCode = "claude_code"
	ToolGeminiCLI  = "gemini_cli"
)

const (
	eventTypeUserPrompt  = "user_prompt"
	eventTypeAPIRequest  = "api_request"
	eventTypeAPIResponse = "api_response"
	eventTypeAPIError    = "api_error"
	eventTypeToolResult  = "tool_result"
	eventTypeToolCall    = "tool_call"
)

func NewOTELReceiver(ctx context.Context, grpcAddr string, exporter *export.Exporter) (*OTELReceiver, error) {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", grpcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", grpcAddr, err)
	}

	receiver := &OTELReceiver{
		grpcServer: grpc.NewServer(),
		listener:   listener,
		eventChan:  make(chan *export.RecordAgentEvent, export.ExportChannelSize),
		exporter:   exporter,
	}

	collogspb.RegisterLogsServiceServer(receiver.grpcServer, receiver)

	return receiver, nil
}

func (r *OTELReceiver) Start(ctx context.Context) {
	log.Info().Str("addr", r.listener.Addr().String()).Msg("starting OTEL receiver")
	go r.exporter.IngestAgentEvent(ctx, r.eventChan)
	go func() {
		if err := r.grpcServer.Serve(r.listener); err != nil {
			log.Error().Err(err).Msg("OTEL gRPC server error")
		}
	}()

	<-ctx.Done()
}

// Export implements the OTLP LogsService Export RPC
func (r *OTELReceiver) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	for _, resourceLogs := range req.GetResourceLogs() {
		for _, scopeLogs := range resourceLogs.GetScopeLogs() {
			for _, logRecord := range scopeLogs.GetLogRecords() {
				event := r.parseLogRecord(logRecord)
				if event != nil {
					select {
					case r.eventChan <- event:
					default:
						log.Warn().Msg("OTEL event channel full, dropping event")
					}
				}
			}
		}
	}

	return &collogspb.ExportLogsServiceResponse{}, nil
}

func (r *OTELReceiver) parseLogRecord(record *logspb.LogRecord) *export.RecordAgentEvent {
	attrs := extractAttributes(record.GetAttributes())

	eventName := getStringAttr(attrs, "event.name")
	if eventName == "" {
		return nil
	}

	tool, eventType := parseEventName(eventName)
	if tool == "" {
		return nil
	}
	// only collect the user prompt & tool use for now
	if eventType != eventTypeUserPrompt && eventType != eventTypeToolCall && eventType != eventTypeToolResult {
		return nil
	}

	timestamp := time.Unix(0, int64(record.GetTimeUnixNano()))

	event := &export.RecordAgentEvent{
		Timestamp: timestamp,
		Tool:      tool,
		EventName: eventName,
		EventType: eventType,
	}

	// Set common fields based on tool
	switch tool {
	case ToolCodex:
		event.ConversationID = getStringAttr(attrs, "conversation.id")
		event.Model = getStringAttr(attrs, "model")
		event.Slug = getStringAttr(attrs, "slug")
		event.AppVersion = getStringAttr(attrs, "app.version")
	case ToolClaudeCode:
		event.SessionID = getStringAttr(attrs, "session.id")
		event.Model = getStringAttr(attrs, "model")
		event.AppVersion = getStringAttr(attrs, "app.version")
	case ToolGeminiCLI:
		event.SessionID = getStringAttr(attrs, "sessionId")
		event.Model = getStringAttr(attrs, "model")
	}

	// Store all attributes as JSON
	if attrsJSON, err := protojson.Marshal(&commonpb.KeyValueList{Values: record.GetAttributes()}); err == nil {
		event.Attributes = attrsJSON
	}

	// Parse event-specific fields based on event type
	switch eventType {
	case eventTypeUserPrompt:
		event.Prompt = getStringAttr(attrs, "prompt")
		event.PromptLength = parseIntAttr(attrs, "prompt_length")

	case eventTypeToolResult, eventTypeToolCall:
		event.ToolName = coalesce(
			getStringAttr(attrs, "tool_name"),
			getStringAttr(attrs, "function_name"),
		)
		event.CallID = getStringAttr(attrs, "call_id")
		event.Arguments = coalesce(
			getStringAttr(attrs, "arguments"),
			getStringAttr(attrs, "function_args"),
		)
		event.Output = getStringAttr(attrs, "output")
		event.Success = getBoolAttr(attrs, "success")
		event.DurationMs = parseIntAttr(attrs, "duration_ms")
		event.Decision = getStringAttr(attrs, "decision")
		event.ErrorMsg = getStringAttr(attrs, "error")

	case eventTypeAPIRequest:
		event.DurationMs = parseIntAttr(attrs, "duration_ms")
		event.StatusCode = parseIntAttr(attrs, "status_code")
		event.CostUSD = parseFloatAttr(attrs, "cost_usd")

	case eventTypeAPIResponse:
		event.DurationMs = parseIntAttr(attrs, "duration_ms")
		event.StatusCode = parseIntAttr(attrs, "status_code")
		event.InputTokenCount = parseIntAttr(attrs, firstAttrKey(attrs, "input_token_count", "input_tokens"))
		event.OutputTokenCount = parseIntAttr(attrs, firstAttrKey(attrs, "output_token_count", "output_tokens"))
		event.CachedTokenCount = parseIntAttr(attrs, firstAttrKey(attrs, "cached_token_count", "cache_read_tokens", "cached_content_token_count"))
		event.CostUSD = parseFloatAttr(attrs, "cost_usd")

	case eventTypeAPIError:
		event.ErrorMsg = getStringAttr(attrs, "error")
		event.StatusCode = parseIntAttr(attrs, "status_code")
		event.DurationMs = parseIntAttr(attrs, "duration_ms")
	}

	// Handle Codex-specific sse_event with response.completed
	if tool == ToolCodex && eventName == "codex.sse_event" && getStringAttr(attrs, "event.kind") == "response.completed" {
		event.InputTokenCount = parseIntAttr(attrs, "input_token_count")
		event.OutputTokenCount = parseIntAttr(attrs, "output_token_count")
		event.CachedTokenCount = parseIntAttr(attrs, "cached_token_count")
		event.ReasoningTokenCount = parseIntAttr(attrs, "reasoning_token_count")
	}

	log.Debug().
		Str("agent", tool).
		Str("event", eventName).
		Str("type", eventType).
		Str("prompt", event.Prompt).
		Str("tool", event.ToolName).
		Msg("received AI tool OTEL event")

	return event
}

func extractAttributes(attrs []*commonpb.KeyValue) map[string]*commonpb.AnyValue {
	result := make(map[string]*commonpb.AnyValue, len(attrs))
	for _, kv := range attrs {
		key := kv.GetKey()
		value := kv.GetValue()
		if value == nil {
			continue
		}

		result[key] = value
	}
	return result
}

func parseEventName(eventName string) (string, string) {
	for _, prefix := range []string{ToolCodex, ToolClaudeCode, ToolGeminiCLI} {
		if len(eventName) > len(prefix)+1 && eventName[:len(prefix)+1] == prefix+"." {
			return prefix, eventName[len(prefix)+1:]
		}
	}
	return "", ""
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstAttrKey(attrs map[string]*commonpb.AnyValue, keys ...string) string {
	for _, key := range keys {
		if _, ok := attrs[key]; ok {
			return key
		}
	}
	return ""
}

func getStringAttr(attrs map[string]*commonpb.AnyValue, key string) string {
	value, ok := attrs[key]
	if !ok {
		return ""
	}

	switch v := value.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return v.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(v.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(v.DoubleValue, 'g', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		if v.BoolValue {
			return "true"
		}
		return "false"
	}
	return ""
}

func getBoolAttr(attrs map[string]*commonpb.AnyValue, key string) bool {
	value, ok := attrs[key]
	if !ok {
		return false
	}

	switch v := value.GetValue().(type) {
	case *commonpb.AnyValue_BoolValue:
		return v.BoolValue
	case *commonpb.AnyValue_StringValue:
		parsed, err := strconv.ParseBool(v.StringValue)
		if err != nil {
			return false
		}
		return parsed
	}
	return false
}

func parseIntAttr(attrs map[string]*commonpb.AnyValue, key string) int64 {
	value, ok := attrs[key]
	if !ok || key == "" {
		return 0
	}

	switch v := value.GetValue().(type) {
	case *commonpb.AnyValue_IntValue:
		return v.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return int64(v.DoubleValue)
	case *commonpb.AnyValue_StringValue:
		parsed, err := strconv.ParseInt(v.StringValue, 10, 64)
		if err != nil {
			return 0
		}
		return parsed
	}
	return 0
}

func parseFloatAttr(attrs map[string]*commonpb.AnyValue, key string) float64 {
	value, ok := attrs[key]
	if !ok || key == "" {
		return 0
	}

	switch v := value.GetValue().(type) {
	case *commonpb.AnyValue_DoubleValue:
		return v.DoubleValue
	case *commonpb.AnyValue_IntValue:
		return float64(v.IntValue)
	case *commonpb.AnyValue_StringValue:
		parsed, err := strconv.ParseFloat(v.StringValue, 64)
		if err != nil {
			return 0
		}
		return parsed
	}
	return 0
}

func (r *OTELReceiver) Close() {
	r.grpcServer.GracefulStop()
	close(r.eventChan)
}

package tui

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tensorchord/watchu/export"
)

func parseJSONLRecord(line []byte) (displayRecord, error) {
	var record export.JSONLRecord
	if err := json.Unmarshal(line, &record); err != nil {
		return displayRecord{}, fmt.Errorf("decode jsonl record: %w", err)
	}
	raw, err := json.Marshal(record.Event)
	if err != nil {
		return displayRecord{}, fmt.Errorf("marshal event detail: %w", err)
	}

	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		return displayRecord{}, fmt.Errorf("decode event payload: %w", err)
	}

	def := endpointDefinitionFor(record.Endpoint)
	provider, model := httpProviderModel(record.Endpoint, event)
	return displayRecord{
		Endpoint:   record.Endpoint,
		Timestamp:  eventTimestamp(event, record.Timestamp),
		SessionKey: fieldString(event, "session_key"),
		Provider:   provider,
		Model:      model,
		Summary:    def.Summarize(event, raw),
		Detail:     renderEventDetail(def, raw),
	}, nil
}

func renderEventDetail(def endpointDefinition, raw []byte) string {
	if def.TransformDetail != nil {
		raw = def.TransformDetail(raw)
	}

	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return string(raw)
	}
	return out.String()
}

func rewriteHTTPBodyForDisplay(raw []byte) []byte {
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		return raw
	}

	body, ok := event["body"]
	if !ok {
		return raw
	}
	bodyString, ok := body.(string)
	if !ok {
		return raw
	}
	decoded, err := base64.StdEncoding.DecodeString(bodyString)
	if err != nil {
		return raw
	}

	if isPrintableUTF8(decoded) {
		event["body"] = string(decoded)
	} else {
		event["body"] = fmt.Sprintf("<binary body, %d bytes>", len(decoded))
	}

	updated, err := json.Marshal(event)
	if err != nil {
		return raw
	}
	return updated
}

func fieldString(event map[string]any, key string) string {
	v, ok := event[key]
	if !ok || v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	default:
		return fmt.Sprint(val)
	}
}

func httpProviderModel(endpoint string, event map[string]any) (string, string) {
	if endpoint != "http_request" && endpoint != "http_response" {
		return "", ""
	}

	urlString := fieldString(event, "url")
	provider := providerFromURL(urlString)
	model := modelFromHTTPEvent(event)
	if model == "" && provider == "gemini" {
		model = geminiModelFromURL(urlString)
	}
	if model == "" {
		return "", ""
	}
	return provider, model
}

func modelFromHTTPEvent(event map[string]any) string {
	bodyString := fieldString(event, "body")
	if bodyString == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(bodyString)
	if err != nil || len(decoded) == 0 {
		return ""
	}

	var body map[string]any
	if err := json.Unmarshal(decoded, &body); err != nil {
		return ""
	}
	return fieldString(body, "model")
}

func providerFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())

	switch {
	case host == "localhost" || host == "127.0.0.1" || host == "::1":
		return "local"
	case host == "openai.com" || strings.HasSuffix(host, ".openai.com"):
		return "openai"
	case host == "anthropic.com" || strings.HasSuffix(host, ".anthropic.com"):
		return "anthropic"
	case host == "groq.com" || strings.HasSuffix(host, ".groq.com"):
		return "groq"
	case host == "mistral.ai" || strings.HasSuffix(host, ".mistral.ai"):
		return "mistral"
	case host == "generativelanguage.googleapis.com" || strings.HasSuffix(host, ".generativelanguage.googleapis.com"):
		return "gemini"
	case host == "ollama.com" || strings.HasSuffix(host, ".ollama.com"):
		return "ollama"
	default:
		return ""
	}
}

func geminiModelFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	path := parsed.EscapedPath()
	start := strings.Index(path, "/models/")
	if start < 0 {
		return ""
	}
	model := path[start+len("/models/"):]
	if idx := strings.IndexByte(model, ':'); idx >= 0 {
		model = model[:idx]
	}
	return model
}

func isPrintableUTF8(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	for _, r := range string(data) {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func eventTimestamp(event map[string]any, fallback time.Time) time.Time {
	raw := fieldString(event, "timestamp")
	if raw == "" {
		return fallback
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return fallback
	}
	return ts
}

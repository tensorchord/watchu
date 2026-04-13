package tui

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	return displayRecord{
		Endpoint:  record.Endpoint,
		Timestamp: record.Timestamp,
		Summary:   def.Summarize(event, raw),
		Detail:    renderEventDetail(def, raw),
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

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const allTab = "all"

type endpointDefinition struct {
	Style           lipgloss.Style
	Summarize       func(map[string]any, []byte) string
	TransformDetail func([]byte) []byte
}

var spinnerFrames = []string{"-", "\\", "|", "/"}

var endpointOrder = []string{
	"exec_event",
	"tcp_connect",
	"http_request",
	"http_response",
	"file_op",
	"mcp_stdio",
	"pg_event",
	"agent_event",
}

var tabOrder = append([]string{allTab}, endpointOrder...)

var defaultEndpointStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("7")).Padding(0, 1)

var endpointDefinitions = map[string]endpointDefinition{
	"exec_event": {
		Style:     lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("2")).Padding(0, 1),
		Summarize: summarizeExec,
	},
	"http_request": {
		Style:           lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("3")).Padding(0, 1),
		Summarize:       summarizeHTTPRequest,
		TransformDetail: rewriteHTTPBodyForDisplay,
	},
	"http_response": {
		Style:           lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("6")).Padding(0, 1),
		Summarize:       summarizeHTTPResponse,
		TransformDetail: rewriteHTTPBodyForDisplay,
	},
	"mcp_stdio": {
		Style:     lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Background(lipgloss.Color("5")).Padding(0, 1),
		Summarize: summarizeMCPStdIO,
	},
	"pg_event": {
		Style:     lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Background(lipgloss.Color("1")).Padding(0, 1),
		Summarize: summarizePostgres,
	},
	"file_op": {
		Style:     lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("11")).Padding(0, 1),
		Summarize: summarizeFileOp,
	},
	"tcp_connect": {
		Style:     lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("4")).Padding(0, 1),
		Summarize: summarizeTCPConnect,
	},
	"agent_event": {
		Style:     lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("14")).Padding(0, 1),
		Summarize: summarizeAgentEvent,
	},
}

func endpointDefinitionFor(endpoint string) endpointDefinition {
	def, ok := endpointDefinitions[endpoint]
	if !ok {
		return endpointDefinition{
			Style:     defaultEndpointStyle,
			Summarize: summarizeDefault,
		}
	}
	if def.Summarize == nil {
		def.Summarize = summarizeDefault
	}
	return def
}

func summarizeExec(event map[string]any, _ []byte) string {
	args := strings.TrimSpace(fieldString(event, "args"))
	if args != "" {
		return args
	}
	return fieldString(event, "comm")
}

func summarizeHTTPRequest(event map[string]any, _ []byte) string {
	return strings.TrimSpace(fieldString(event, "method") + " " + fieldString(event, "url"))
}

func summarizeHTTPResponse(event map[string]any, _ []byte) string {
	return fmt.Sprintf("status=%v protocol=%s comm=%s", event["status_code"], fieldString(event, "protocol"), fieldString(event, "comm"))
}

func summarizeMCPStdIO(event map[string]any, _ []byte) string {
	return strings.TrimSpace(fieldString(event, "message_type") + " " + fieldString(event, "method"))
}

func summarizePostgres(event map[string]any, _ []byte) string {
	return strings.TrimSpace(fieldString(event, "comm") + " msg=" + fieldString(event, "msg_type"))
}

func summarizeFileOp(event map[string]any, _ []byte) string {
	op := fieldString(event, "op")
	path := fieldString(event, "path")
	newPath := fieldString(event, "new_path")
	if newPath != "" {
		return fmt.Sprintf("%s %s -> %s", op, path, newPath)
	}
	return strings.TrimSpace(op + " " + path)
}

func summarizeTCPConnect(event map[string]any, _ []byte) string {
	return fmt.Sprintf("%s -> %s:%v", fieldString(event, "comm"), fieldString(event, "target_addr"), event["target_port"])
}

func summarizeAgentEvent(event map[string]any, _ []byte) string {
	return strings.TrimSpace(fieldString(event, "tool") + " " + fieldString(event, "event_name"))
}

func summarizeDefault(event map[string]any, raw []byte) string {
	if method := fieldString(event, "method"); method != "" {
		return method
	}
	if op := fieldString(event, "op"); op != "" {
		return op
	}
	return string(raw)
}
